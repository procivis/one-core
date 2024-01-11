use shared_types::{DidId, DidValue};
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;

use crate::model::did::KeyRole;
use crate::model::{
    credential::{
        Credential, CredentialId, CredentialRelations, CredentialStateEnum,
        CredentialStateRelations,
    },
    did::Did,
    revocation_list::{RevocationList, RevocationListId, RevocationListRelations},
};
use crate::provider::credential_formatter::{
    model::CredentialStatus, status_list_2021_jwt_formatter::StatusList2021JWTFormatter,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::{CredentialRevocationInfo, RevocationMethod};
use crate::provider::transport_protocol::TransportProtocolError;
use crate::repository::{
    credential_repository::CredentialRepository,
    revocation_list_repository::RevocationListRepository,
};
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::util::bitstring::{extract_bitstring_index, generate_bitstring};
use crate::util::key_verification::KeyVerification;

pub(crate) struct StatusList2021 {
    pub core_base_url: Option<String>,
    pub credential_repository: Arc<dyn CredentialRepository>,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
    pub key_provider: Arc<dyn KeyProvider + Send + Sync>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub client: reqwest::Client,
}

const CREDENTIAL_STATUS_TYPE: &str = "StatusList2021Entry";

#[async_trait::async_trait]
impl RevocationMethod for StatusList2021 {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Option<CredentialRevocationInfo>, ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?;

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(&issuer_did.id, &RevocationListRelations::default())
            .await?;
        let revocation_list_id = match revocation_list {
            Some(value) => value.id,
            None => {
                let encoded_list = self
                    .generate_bitstring_from_credentials(&issuer_did.id, None)
                    .await?;

                let revocation_list_id = RevocationListId::new_v4();
                let list_credential = self
                    .format_status_list_credential(&revocation_list_id, issuer_did, encoded_list)
                    .await?;

                let now = OffsetDateTime::now_utc();
                self.revocation_list_repository
                    .create_revocation_list(RevocationList {
                        id: revocation_list_id,
                        created_date: now,
                        last_modified: now,
                        credentials: list_credential.as_bytes().to_vec(),
                        issuer_did: Some(issuer_did.to_owned()),
                    })
                    .await?
            }
        };

        let index_on_status_list = self
            .get_credential_index_on_revocation_list(&credential.id, &issuer_did.id)
            .await?;

        Ok(Some(CredentialRevocationInfo {
            additional_vc_contexts: vec!["https://w3id.org/vc/status-list/2021/v1".to_string()],
            credential_status: self
                .create_credential_status(&revocation_list_id, index_on_status_list)?,
        }))
    }

    async fn mark_credential_revoked(&self, credential: &Credential) -> Result<(), ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(&issuer_did.id, &RevocationListRelations::default())
            .await?;

        let Some(revocation_list) = revocation_list else {
            return Err(BusinessLogicError::MissingRevocationListForDid {
                did_id: issuer_did.id,
            }
            .into());
        };

        let encoded_list = self
            .generate_bitstring_from_credentials(&issuer_did.id, Some(credential.id))
            .await?;

        let list_credential = self
            .format_status_list_credential(&revocation_list.id, &issuer_did, encoded_list)
            .await?;

        self.revocation_list_repository
            .update_credentials(&revocation_list.id, list_credential.as_bytes().to_vec())
            .await?;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
    ) -> Result<bool, ServiceError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(ServiceError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get("statusListCredential")
            .ok_or(ServiceError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get("statusListIndex")
            .ok_or(ServiceError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| ServiceError::ValidationError("Invalid list index".to_string()))?;

        let response = self
            .client
            .get(list_url)
            .send()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response = response
            .error_for_status()
            .map_err(TransportProtocolError::HttpRequestError)?;
        let response_value = response
            .text()
            .await
            .map_err(TransportProtocolError::HttpRequestError)?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let encoded_list = StatusList2021JWTFormatter::parse_status_list(
            &response_value,
            issuer_did,
            key_verification,
        )
        .await?;

        let result = extract_bitstring_index(encoded_list, list_index)?;
        Ok(result)
    }
}

impl StatusList2021 {
    async fn get_credential_index_on_revocation_list(
        &self,
        credential_id: &CredentialId,
        issuer_did_id: &DidId,
    ) -> Result<usize, ServiceError> {
        let list = self
            .credential_repository
            .get_credentials_by_issuer_did_id(issuer_did_id, &CredentialRelations::default())
            .await?;

        let index = list
            .iter()
            .position(|credential| credential.id == *credential_id)
            .ok_or(BusinessLogicError::MissingCredentialIndexOnRevocationList {
                credential_id: *credential_id,
                did: *issuer_did_id,
            })?;

        Ok(index)
    }

    async fn generate_bitstring_from_credentials(
        &self,
        issuer_did_id: &DidId,
        additionally_revoked_credential_id: Option<CredentialId>,
    ) -> Result<String, ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_issuer_did_id(
                issuer_did_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let states = credentials
            .into_iter()
            .map(|credential| {
                if additionally_revoked_credential_id
                    .is_some_and(|credential_id| credential_id == credential.id)
                {
                    return Ok(true);
                }

                let states = credential
                    .state
                    .ok_or(ServiceError::MappingError("state is None".to_string()))?;

                match states
                    .first()
                    .ok_or(ServiceError::MappingError(
                        "latest state not found".to_string(),
                    ))?
                    .state
                {
                    CredentialStateEnum::Revoked => Ok(true),
                    _ => Ok(false),
                }
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;

        generate_bitstring(states).map_err(ServiceError::from)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
    ) -> Result<CredentialStatus, ServiceError> {
        let revocation_list_url = self.get_revocation_list_url(revocation_list_id)?;
        Ok(CredentialStatus {
            id: format!("{}#{}", revocation_list_url, index_on_status_list),
            r#type: CREDENTIAL_STATUS_TYPE.to_string(),
            status_purpose: "revocation".to_string(),
            additional_fields: HashMap::from([
                ("statusListCredential".to_string(), revocation_list_url),
                (
                    "statusListIndex".to_string(),
                    index_on_status_list.to_string(),
                ),
            ]),
        })
    }

    async fn format_status_list_credential(
        &self,
        revocation_list_id: &RevocationListId,
        issuer_did: &Did,
        encoded_list: String,
    ) -> Result<String, ServiceError> {
        let revocation_list_url = self.get_revocation_list_url(revocation_list_id)?;

        let keys = issuer_did
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("Issuer has no keys".to_string()))?;

        let key = keys
            .iter()
            .find(|k| k.role == KeyRole::AssertionMethod)
            .ok_or(ServiceError::Other("Missing Key".to_owned()))?;

        let auth_fn = self.key_provider.get_signature_provider(&key.key)?;

        StatusList2021JWTFormatter::format_status_list(
            revocation_list_url,
            issuer_did,
            encoded_list,
            key.key.key_type.to_owned(),
            auth_fn,
        )
        .await
        .map_err(ServiceError::from)
    }

    fn get_revocation_list_url(
        &self,
        revocation_list_id: &RevocationListId,
    ) -> Result<String, ServiceError> {
        Ok(format!(
            "{}/ssi/revocation/v1/list/{}",
            self.core_base_url
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "Host URL not specified".to_string()
                ))?,
            revocation_list_id
        ))
    }
}
