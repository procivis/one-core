use anyhow::Context;
use one_providers::did::provider::DidMethodProvider;
use one_providers::key_algorithm::provider::KeyAlgorithmProvider;
use one_providers::key_storage::provider::KeyProvider;
use shared_types::{CredentialId, DidId, DidValue};
use std::collections::HashMap;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, CredentialStateRelations,
};
use crate::model::did::{Did, KeyRole};
use crate::model::revocation_list::{
    RevocationList, RevocationListId, RevocationListPurpose, RevocationListRelations,
};
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::credential_formatter::status_list_jwt_formatter::common::StatusPurpose;
use crate::provider::credential_formatter::status_list_jwt_formatter::BitstringStatusListJwtFormatter;
use crate::provider::exchange_protocol::ExchangeProtocolError;
use crate::provider::revocation::{
    CredentialDataByRole, CredentialRevocationInfo, CredentialRevocationState, JsonLdContext,
    RevocationMethod, RevocationMethodCapabilities,
};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::util::bitstring::{extract_bitstring_index, generate_bitstring};
use crate::util::key_verification::KeyVerification;

const CREDENTIAL_STATUS_TYPE: &str = "BitstringStatusListEntry";

pub(crate) struct BitstringStatusList {
    pub core_base_url: Option<String>,
    pub credential_repository: Arc<dyn CredentialRepository>,
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
    pub key_provider: Arc<dyn KeyProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub client: reqwest::Client,
}

#[async_trait::async_trait]
impl RevocationMethod for BitstringStatusList {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
    ) -> Result<Vec<CredentialRevocationInfo>, ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?;

        let revocation_list_id = self
            .get_revocation_list_id(issuer_did, RevocationListPurpose::Revocation)
            .await?;
        let suspension_list_id = self
            .get_revocation_list_id(issuer_did, RevocationListPurpose::Suspension)
            .await?;

        let index_on_status_list = self
            .get_credential_index_on_revocation_list(&credential.id, &issuer_did.id)
            .await?;

        Ok(vec![
            CredentialRevocationInfo {
                credential_status: self.create_credential_status(
                    &revocation_list_id,
                    index_on_status_list,
                    "revocation",
                )?,
            },
            CredentialRevocationInfo {
                credential_status: self.create_credential_status(
                    &suspension_list_id,
                    index_on_status_list,
                    "suspension",
                )?,
            },
        ])
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
    ) -> Result<(), ServiceError> {
        match new_state {
            CredentialRevocationState::Revoked => {
                self.mark_credential_as_impl(RevocationListPurpose::Revocation, credential, true)
                    .await
            }
            CredentialRevocationState::Valid => {
                self.mark_credential_as_impl(RevocationListPurpose::Suspension, credential, false)
                    .await
            }
            CredentialRevocationState::Suspended { .. } => {
                self.mark_credential_as_impl(RevocationListPurpose::Suspension, credential, true)
                    .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, ServiceError> {
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
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response_value = response
            .text()
            .await
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let encoded_list = BitstringStatusListJwtFormatter::parse_status_list(
            &response_value,
            issuer_did,
            key_verification,
        )
        .await?;

        if extract_bitstring_index(encoded_list, list_index)? {
            Ok(match credential_status.status_purpose.as_ref() {
                Some(purpose) => match purpose.as_str() {
                    "revocation" => CredentialRevocationState::Revoked,
                    "suspension" => CredentialRevocationState::Suspended {
                        suspend_end_date: None,
                    },
                    _ => {
                        return Err(ServiceError::ValidationError(format!(
                            "Invalid status purpose: {purpose}",
                        )))
                    }
                },
                None => {
                    return Err(ServiceError::ValidationError(
                        "Missing status purpose ".to_string(),
                    ))
                }
            })
        } else {
            Ok(CredentialRevocationState::Valid)
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec!["REVOKE".to_string(), "SUSPEND".to_string()],
        }
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, ServiceError> {
        Ok(JsonLdContext::default())
    }
}

impl BitstringStatusList {
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
        matching_state: CredentialStateEnum,
        additionally_changed_credential: Option<BitstringCredentialInfo>,
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
            .await?;

        let states = credentials
            .into_iter()
            .map(|credential| {
                if let Some(changed_credential) = additionally_changed_credential.as_ref() {
                    if changed_credential.credential_id == credential.id {
                        return Ok(changed_credential.value);
                    }
                }

                let states = credential
                    .state
                    .ok_or(ServiceError::MappingError("state is None".to_string()))?;

                let latest_state = states
                    .first()
                    .ok_or(ServiceError::MappingError(
                        "latest state not found".to_string(),
                    ))?
                    .state
                    .to_owned();

                Ok(latest_state == matching_state)
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;

        generate_bitstring(states).map_err(ServiceError::from)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
        purpose: &str,
    ) -> Result<CredentialStatus, ServiceError> {
        let revocation_list_url = self.get_revocation_list_url(revocation_list_id)?;
        Ok(CredentialStatus {
            id: format!("{}#{}", revocation_list_url, index_on_status_list),
            r#type: CREDENTIAL_STATUS_TYPE.to_string(),
            status_purpose: Some(purpose.to_string()),
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
        purpose: RevocationListPurpose,
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

        let auth_fn = self
            .key_provider
            .get_signature_provider(&key.key.to_owned(), None)?;

        let status_list = BitstringStatusListJwtFormatter::format_status_list(
            revocation_list_url,
            issuer_did,
            encoded_list,
            key.key.key_type.to_owned(),
            auth_fn,
            purpose_to_bitstring_status_purpose(purpose),
        )
        .await?;

        Ok(status_list)
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

    async fn mark_credential_as_impl(
        &self,
        purpose: RevocationListPurpose,
        credential: &Credential,
        new_revocation_value: bool,
    ) -> Result<(), ServiceError> {
        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(ServiceError::MappingError("issuer did is None".to_string()))?
            .clone();

        let revocation_list_id = self
            .get_revocation_list_id(&issuer_did, purpose.to_owned())
            .await?;

        let encoded_list = self
            .generate_bitstring_from_credentials(
                &issuer_did.id,
                purpose_to_credential_state_enum(purpose.to_owned()),
                Some(BitstringCredentialInfo {
                    credential_id: credential.id,
                    value: new_revocation_value,
                }),
            )
            .await?;

        let list_credential = self
            .format_status_list_credential(&revocation_list_id, &issuer_did, encoded_list, purpose)
            .await?;

        self.revocation_list_repository
            .update_credentials(&revocation_list_id, list_credential.as_bytes().to_vec())
            .await?;

        Ok(())
    }

    async fn get_revocation_list_id(
        &self,
        issuer_did: &Did,
        purpose: RevocationListPurpose,
    ) -> Result<RevocationListId, ServiceError> {
        let revocation_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_did_id(
                &issuer_did.id,
                purpose.to_owned(),
                &RevocationListRelations::default(),
            )
            .await?;

        let credential_state = purpose_to_credential_state_enum(purpose.to_owned());

        Ok(match revocation_list {
            Some(value) => value.id,
            None => {
                let encoded_list = self
                    .generate_bitstring_from_credentials(&issuer_did.id, credential_state, None)
                    .await?;

                let revocation_list_id = Uuid::new_v4();
                let list_credential = self
                    .format_status_list_credential(
                        &revocation_list_id,
                        issuer_did,
                        encoded_list,
                        purpose.to_owned(),
                    )
                    .await?;

                let now = OffsetDateTime::now_utc();
                self.revocation_list_repository
                    .create_revocation_list(RevocationList {
                        id: revocation_list_id,
                        created_date: now,
                        last_modified: now,
                        credentials: list_credential.into_bytes(),
                        purpose,
                        issuer_did: Some(issuer_did.to_owned()),
                    })
                    .await?
            }
        })
    }
}

struct BitstringCredentialInfo {
    pub credential_id: CredentialId,
    pub value: bool,
}

fn purpose_to_credential_state_enum(purpose: RevocationListPurpose) -> CredentialStateEnum {
    match purpose {
        RevocationListPurpose::Revocation => CredentialStateEnum::Revoked,
        RevocationListPurpose::Suspension => CredentialStateEnum::Suspended,
    }
}

fn purpose_to_bitstring_status_purpose(purpose: RevocationListPurpose) -> StatusPurpose {
    match purpose {
        RevocationListPurpose::Revocation => StatusPurpose::Revocation,
        RevocationListPurpose::Suspension => StatusPurpose::Suspension,
    }
}
