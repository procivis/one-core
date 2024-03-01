use std::{collections::HashMap, str::FromStr, sync::Arc};

use serde::Deserialize;
use serde_with::DurationSeconds;
use shared_types::{CredentialId, DidValue};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    model::{credential::Credential, did::KeyRole},
    provider::{
        credential_formatter::{
            model::CredentialStatus, provider::CredentialFormatterProvider, CredentialData,
            CredentialFormatter,
        },
        did_method::provider::DidMethodProvider,
        key_algorithm::provider::KeyAlgorithmProvider,
        key_storage::provider::KeyProvider,
        revocation::RevocationMethod,
    },
    repository::lvvc_repository::LvvcRepository,
    service::error::{BusinessLogicError, MissingProviderError, ServiceError},
    util::key_verification::KeyVerification,
};

use super::CredentialRevocationInfo;

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub credential_expiry: time::Duration,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    params: Params,
}

impl LvvcProvider {
    pub(crate) fn new(
        core_base_url: Option<String>,
        lvvc_repository: Arc<dyn LvvcRepository>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            lvvc_repository,
            credential_formatter,
            params,
            key_provider,
            key_algorithm_provider,
            did_method_provider,
        }
    }

    fn key_verifier(&self) -> Box<KeyVerification> {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        })
    }

    fn formatter(
        &self,
        credential: &Credential,
    ) -> Result<Arc<dyn CredentialFormatter>, ServiceError> {
        let format = credential
            .schema
            .as_ref()
            .map(|schema| schema.format.as_str())
            .ok_or(BusinessLogicError::MissingCredentialSchema)?;

        let formatter = self
            .credential_formatter
            .get_formatter(format)
            .ok_or_else(|| MissingProviderError::Formatter(format.to_owned()))?;

        Ok(formatter)
    }

    async fn create_lvvc_with_status(
        &self,
        credential: &Credential,
        status: Status,
    ) -> Result<(), ServiceError> {
        let base_url = self.core_base_url.as_ref().ok_or_else(|| {
            ServiceError::MappingError("LVVC issuance is missing core base_url".to_string())
        })?;
        let issuer_did = credential.issuer_did.as_ref().ok_or_else(|| {
            ServiceError::MappingError("LVVC issuance is missing issuer DID".to_string())
        })?;
        let holder_did = credential.holder_did.as_ref().ok_or_else(|| {
            ServiceError::MappingError("LVVC issuance is missing holder DID".to_string())
        })?;

        let key = issuer_did
            .keys
            .as_ref()
            .and_then(|keys| keys.iter().find(|k| k.role == KeyRole::AssertionMethod))
            .map(|k| &k.key)
            .ok_or_else(|| {
                ServiceError::MappingError("LVVC issuance is missing key".to_string())
            })?;
        let auth_fn = self.key_provider.get_signature_provider(key)?;

        let lvvc_credential_id = Uuid::new_v4();
        let credential_data = CredentialData {
            id: format!("{base_url}/ssi/lvvc/v1/{lvvc_credential_id}"),
            issuance_date: OffsetDateTime::now_utc(),
            valid_for: self.params.credential_expiry,
            claims: vec![id_claim(base_url, credential.id), status_claim(status)],
            issuer_did: issuer_did.did.to_owned(),
            credential_schema: None,
            credential_status: None,
        };

        let formatter = self.formatter(credential)?;
        let formatted_credential = formatter
            .format_credentials(
                credential_data,
                &holder_did.did,
                &key.key_type,
                vec![],
                vec![],
                auth_fn,
            )
            .await?;

        let lvvc_credential = crate::model::lvvc::Lvvc {
            id: lvvc_credential_id,
            created_date: OffsetDateTime::now_utc(),
            credential: formatted_credential.into_bytes(),
            linked_credential_id: credential.id,
        };

        Ok(self.lvvc_repository.insert(lvvc_credential).await?)
    }
}

#[async_trait::async_trait]
impl RevocationMethod for LvvcProvider {
    fn get_status_type(&self) -> String {
        "LVVC".to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        let base_url = self.core_base_url.as_ref().ok_or_else(|| {
            ServiceError::MappingError("LVVC issuance is missing core base_url".to_string())
        })?;

        self.create_lvvc_with_status(credential, Status::Accepted)
            .await?;

        Ok(Some(CredentialRevocationInfo {
            credential_status: CredentialStatus {
                id: format!("{base_url}/ssi/revocation/v1/lvvc/{}", credential.id),
                r#type: self.get_status_type(),
                status_purpose: None,
                additional_fields: HashMap::new(),
            },
        }))
    }

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError> {
        let formatter = self.formatter(credential)?;

        let latest_lvvc = self
            .lvvc_repository
            .get_latest_by_credential_id(credential.id)
            .await?
            .ok_or_else(|| {
                ServiceError::Revocation(format!("Missing LVVC for credential: {}", credential.id))
            })?;

        let lvvc_credential = String::from_utf8_lossy(&latest_lvvc.credential);
        let lvvc_credential = formatter
            .extract_credentials(&lvvc_credential, self.key_verifier())
            .await?;

        let status = lvvc_credential.claims.values.get("status").ok_or_else(|| {
            ServiceError::Revocation(format!(
                "LVVC `{}` is missing `subject` claim",
                latest_lvvc.id
            ))
        })?;

        match Status::from_str(status) {
            Err(err) => {
                return Err(ServiceError::Revocation(format!(
                    "Invalid LVVC status claim: {err}"
                )));
            }
            Ok(Status::Revoked) => {
                return Err(BusinessLogicError::CredentialAlreadyRevoked.into());
            }
            Ok(Status::Accepted) => {
                self.create_lvvc_with_status(credential, Status::Revoked)
                    .await?;
            }
        };

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        _credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
    ) -> Result<bool, ServiceError> {
        unimplemented!()
    }
}

fn id_claim(base_url: &str, credential_id: CredentialId) -> (String, String) {
    (
        "id".to_owned(),
        format!("{base_url}/ssi/credential/v1/{credential_id}"),
    )
}

fn status_claim(status: Status) -> (String, String) {
    ("status".to_owned(), status.to_string())
}

#[derive(strum::Display, strum::EnumString)]
enum Status {
    #[strum(serialize = "ACCEPTED")]
    Accepted,
    #[strum(serialize = "REVOKED")]
    Revoked,
}
