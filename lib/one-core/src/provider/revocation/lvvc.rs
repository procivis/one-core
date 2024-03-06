use std::{collections::HashMap, ops::Sub, str::FromStr, sync::Arc};

use crate::{
    model::{
        credential::{
            Credential, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
        },
        did::{DidRelations, KeyRole},
        key::KeyRelations,
        lvvc::Lvvc,
    },
    provider::{
        credential_formatter::{
            jwt::{model::JWTPayload, Jwt},
            model::CredentialStatus,
            provider::CredentialFormatterProvider,
            CredentialData, CredentialFormatter,
        },
        did_method::provider::DidMethodProvider,
        key_algorithm::provider::KeyAlgorithmProvider,
        key_storage::provider::KeyProvider,
        revocation::RevocationMethod,
        transport_protocol::TransportProtocolError,
    },
    repository::{credential_repository::CredentialRepository, lvvc_repository::LvvcRepository},
    service::{
        error::{BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError},
        ssi_issuer::dto::IssuerResponseDTO,
    },
    util::key_verification::KeyVerification,
};
use serde::{Deserialize, Serialize};
use serde_with::DurationSeconds;
use shared_types::{CredentialId, DidValue};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::{
    CredentialDataByRole, CredentialRevocationInfo, NewCredentialState,
    RevocationMethodCapabilities, VerifierCredentialData,
};

#[serde_with::serde_as]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub credential_expiry: time::Duration,
}

pub struct LvvcProvider {
    core_base_url: Option<String>,
    credential_repository: Arc<dyn CredentialRepository>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    credential_formatter: Arc<dyn CredentialFormatterProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    client: reqwest::Client,
    params: Params,
}

impl LvvcProvider {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        core_base_url: Option<String>,
        credential_repository: Arc<dyn CredentialRepository>,
        lvvc_repository: Arc<dyn LvvcRepository>,
        credential_formatter: Arc<dyn CredentialFormatterProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        client: reqwest::Client,
        params: Params,
    ) -> Self {
        Self {
            core_base_url,
            credential_repository,
            lvvc_repository,
            credential_formatter,
            key_provider,
            key_algorithm_provider,
            did_method_provider,
            client,
            params,
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
        create_lvvc_with_status(
            credential,
            status,
            &self.core_base_url,
            self.params.credential_expiry,
            self.formatter(credential)?,
            self.lvvc_repository.clone(),
            self.key_provider.clone(),
        )
        .await
        .map(|_| ())
    }

    async fn check_revocation_status_as_holder(
        &self,
        credential_id: &CredentialId,
        credential_status: &CredentialStatus,
    ) -> Result<bool, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Credential(credential_id.to_owned()))?;

        let bearer_token = prepare_bearer_token(&credential, self.key_provider.clone()).await?;

        let lvvc_check_url = &credential_status.id;
        let response: IssuerResponseDTO = self
            .client
            .get(lvvc_check_url)
            .bearer_auth(bearer_token)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?
            .json()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        let formatter = self
            .credential_formatter
            .get_formatter(&response.format)
            .ok_or(MissingProviderError::Formatter(response.format))?;

        let lvvc = formatter
            .extract_credentials_unverified(&response.credential)
            .await?;

        let status = lvvc
            .claims
            .values
            .get("status")
            .ok_or(ServiceError::ValidationError(
                "missing status claim in LVVC".to_string(),
            ))?;
        let status_as_enum =
            Status::from_str(status).map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        Ok(status_as_enum == Status::Revoked)
    }

    async fn check_revocation_status_as_issuer(
        &self,
        credential_id: &CredentialId,
    ) -> Result<bool, ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Credential(credential_id.to_owned()))?;

        let states = credential
            .state
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?;

        Ok(latest_state.state == CredentialStateEnum::Revoked)
    }

    fn check_revocation_status_as_verifier(
        &self,
        issuer_did: &DidValue,
        data: VerifierCredentialData,
    ) -> Result<bool, ServiceError> {
        let credential_id = data
            .credential
            .id
            .as_ref()
            .ok_or(ServiceError::ValidationError(
                "credential id missing".to_string(),
            ))?;

        let lvvc = data
            .extracted_lvvcs
            .iter()
            .find(|lvvc| {
                if let Some(id) = lvvc.claims.values.get("id") {
                    *id == *credential_id
                } else {
                    false
                }
            })
            .ok_or(ServiceError::ValidationError(
                "no matching LVVC found among credentials".to_string(),
            ))?;

        let lvvc_issuer_did = lvvc
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::ValidationError(
                "LVVC issuer DID missing".to_string(),
            ))?;

        if issuer_did != lvvc_issuer_did {
            return Err(ServiceError::ValidationError(
                "LVVC issuer DID is not equal to issuer DID".to_string(),
            ));
        }

        let lvvc_issued_at = lvvc.issued_at.ok_or(ServiceError::ValidationError(
            "LVVC issued_at missing".to_string(),
        ))?;
        if let Some(validity_constraint) = data.proof_schema.validity_constraint {
            let now = OffsetDateTime::now_utc();

            if now.sub(Duration::seconds(validity_constraint)) > lvvc_issued_at {
                return Err(ServiceError::ValidationError(
                    "LVVC has expired".to_string(),
                ));
            }
        }

        let lvvc_status = lvvc
            .claims
            .values
            .get("status")
            .ok_or(ServiceError::ValidationError("status is None".to_string()))?;
        let status = Status::from_str(lvvc_status)
            .map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        Ok(status == Status::Revoked)
    }
}

#[async_trait::async_trait]
impl RevocationMethod for LvvcProvider {
    fn get_status_type(&self) -> String {
        "LVVC".to_string()
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
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
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<bool, ServiceError> {
        let additional_credential_data = additional_credential_data.ok_or(
            ServiceError::ValidationError("additional_credential_data is None".to_string()),
        )?;

        match additional_credential_data {
            CredentialDataByRole::Holder(credential_id) => {
                self.check_revocation_status_as_holder(&credential_id, credential_status)
                    .await
            }
            CredentialDataByRole::Issuer(credential_id) => {
                self.check_revocation_status_as_issuer(&credential_id).await
            }
            CredentialDataByRole::Verifier(data) => {
                self.check_revocation_status_as_verifier(issuer_did, *data)
            }
        }
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: NewCredentialState,
    ) -> Result<(), ServiceError> {
        match new_state {
            NewCredentialState::Revoked => self.mark_credential_revoked(credential).await,
            NewCredentialState::Reactivated => todo!(),
            NewCredentialState::Suspended => todo!(),
        }
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

#[derive(PartialEq, strum::Display, strum::EnumString)]
pub(crate) enum Status {
    #[strum(serialize = "ACCEPTED")]
    Accepted,
    #[strum(serialize = "REVOKED")]
    Revoked,
}

pub(crate) async fn create_lvvc_with_status(
    credential: &Credential,
    status: Status,
    core_base_url: &Option<String>,
    credential_expiry: time::Duration,
    formatter: Arc<dyn CredentialFormatter>,
    lvvc_repository: Arc<dyn LvvcRepository>,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<Lvvc, ServiceError> {
    let base_url = core_base_url.as_ref().ok_or_else(|| {
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
        .ok_or_else(|| ServiceError::MappingError("LVVC issuance is missing key".to_string()))?;
    let auth_fn = key_provider.get_signature_provider(key)?;

    let lvvc_credential_id = Uuid::new_v4();
    let credential_data = CredentialData {
        id: format!("{base_url}/ssi/lvvc/v1/{lvvc_credential_id}"),
        issuance_date: OffsetDateTime::now_utc(),
        valid_for: credential_expiry,
        claims: vec![id_claim(base_url, credential.id), status_claim(status)],
        issuer_did: issuer_did.did.to_owned(),
        credential_schema: None,
        credential_status: None,
    };

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

    let lvvc_credential = Lvvc {
        id: lvvc_credential_id,
        created_date: OffsetDateTime::now_utc(),
        credential: formatted_credential.into_bytes(),
        linked_credential_id: credential.id,
    };

    lvvc_repository.insert(lvvc_credential.to_owned()).await?;

    Ok(lvvc_credential)
}

pub(crate) async fn prepare_bearer_token(
    credential: &Credential,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<String, ServiceError> {
    let holder_did = credential
        .holder_did
        .as_ref()
        .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;
    let keys = holder_did
        .keys
        .as_ref()
        .ok_or(ServiceError::MappingError("keys is None".to_string()))?;
    let authentication_key = keys
        .iter()
        .find(|key| key.role == KeyRole::Authentication)
        .ok_or(ServiceError::MappingError(
            "No authentication keys found for holder DID".to_string(),
        ))?;

    let payload = JWTPayload {
        custom: BearerTokenPayload {
            timestamp: OffsetDateTime::now_utc().unix_timestamp(),
        },
        ..Default::default()
    };

    let signer = key_provider.get_signature_provider(&authentication_key.key)?;
    let bearer_token = Jwt::new("JWT".to_string(), "HS256".to_string(), None, payload)
        .tokenize(signer)
        .await?;

    Ok(bearer_token)
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct BearerTokenPayload {
    pub timestamp: i64,
}
