//! Bitstring Status List implementation.

use std::collections::HashMap;
use std::sync::Arc;

use resolver::StatusListResolver;
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId, DidValue};

use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::did::{Did, KeyRole};
use crate::model::revocation_list::RevocationListPurpose;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::bitstring_status_list::model::{
    RevocationUpdateData, StatusPurpose,
};
use crate::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, RevocationListId, RevocationMethodCapabilities,
    RevocationUpdate,
};
use crate::provider::revocation::RevocationMethod;
use crate::service::revocation_list::dto::SupportedBitstringCredentialFormat;
use crate::util::key_verification::KeyVerification;
use crate::util::params::convert_params;

mod jwt_formatter;
pub mod model;
pub mod resolver;
pub mod util;

#[cfg(test)]
mod test;

const CREDENTIAL_STATUS_TYPE: &str = "BitstringStatusListEntry";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    #[serde(default)]
    pub bitstring_credential_format: Option<SupportedBitstringCredentialFormat>,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            bitstring_credential_format: Some(SupportedBitstringCredentialFormat::default()),
        }
    }
}

pub struct BitstringStatusList {
    pub core_base_url: Option<String>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_provider: Arc<dyn KeyProvider>,
    pub caching_loader: StatusListCachingLoader,
    pub formatter_provider: Arc<dyn CredentialFormatterProvider>,
    resolver: Arc<StatusListResolver>,
    params: Params,
}

impl BitstringStatusList {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        core_base_url: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        caching_loader: StatusListCachingLoader,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        client: Arc<dyn HttpClient>,
        params: Option<Params>,
    ) -> Self {
        Self {
            core_base_url,
            key_algorithm_provider,
            did_method_provider,
            key_provider,
            caching_loader,
            formatter_provider,
            resolver: Arc::new(StatusListResolver::new(client)),
            params: params.unwrap_or_default(),
        }
    }
}

#[async_trait::async_trait]
impl RevocationMethod for BitstringStatusList {
    fn get_status_type(&self) -> String {
        CREDENTIAL_STATUS_TYPE.to_string()
    }

    async fn add_issued_credential(
        &self,
        credential: &Credential,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<(Option<RevocationUpdate>, Vec<CredentialRevocationInfo>), RevocationError> {
        let data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let index_on_status_list = self.get_credential_index_on_revocation_list(
            &data.credentials_by_issuer_did,
            &credential.id,
            &issuer_did.id,
        )?;

        let mut revocation_info = vec![CredentialRevocationInfo {
            credential_status: self.create_credential_status(
                &data.revocation_list_id,
                index_on_status_list,
                "revocation",
            )?,
        }];

        if credential_schema.allow_suspension {
            revocation_info.push(CredentialRevocationInfo {
                credential_status: self.create_credential_status(
                    &data.suspension_list_id,
                    index_on_status_list,
                    "suspension",
                )?,
            });
        }

        Ok((None, revocation_info))
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
        additional_data: Option<CredentialAdditionalData>,
    ) -> Result<RevocationUpdate, RevocationError> {
        let additional_data = additional_data.ok_or(RevocationError::MappingError(
            "additional_data is None".to_string(),
        ))?;

        match new_state {
            CredentialRevocationState::Revoked => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Revocation,
                    credential,
                    true,
                    additional_data,
                )
                .await
            }
            CredentialRevocationState::Valid => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Suspension,
                    credential,
                    false,
                    additional_data,
                )
                .await
            }
            CredentialRevocationState::Suspended { .. } => {
                self.mark_credential_as_impl(
                    RevocationListPurpose::Suspension,
                    credential,
                    true,
                    additional_data,
                )
                .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        _issuer_did: &DidValue,
        _additional_credential_data: Option<CredentialDataByRole>,
    ) -> Result<CredentialRevocationState, RevocationError> {
        if credential_status.r#type != CREDENTIAL_STATUS_TYPE {
            return Err(RevocationError::ValidationError(format!(
                "Invalid credential status type: {}",
                credential_status.r#type
            )));
        }

        let list_url = credential_status
            .additional_fields
            .get("statusListCredential")
            .and_then(|url| url.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get("statusListIndex")
            .and_then(|index| index.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| RevocationError::ValidationError("Invalid list index".to_string()))?;

        let response = String::from_utf8(
            self.caching_loader
                .get(list_url, self.resolver.clone())
                .await?,
        )?;

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });

        let status_credential = self
            .get_formatter_for_credential_format()?
            .extract_credentials(&response, key_verification)
            .await?;

        let encoded_list = status_credential
            .claims
            .values
            .get("encodedList")
            .and_then(|value| value.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing encodedList in status credential".to_string(),
            ))?;

        if util::extract_bitstring_index(encoded_list.to_owned(), list_index)? {
            Ok(match credential_status.status_purpose.as_ref() {
                Some(purpose) => match purpose.as_str() {
                    "revocation" => CredentialRevocationState::Revoked,
                    "suspension" => CredentialRevocationState::Suspended {
                        suspend_end_date: None,
                    },
                    _ => {
                        return Err(RevocationError::ValidationError(format!(
                            "Invalid status purpose: {purpose}",
                        )))
                    }
                },
                None => {
                    return Err(RevocationError::ValidationError(
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

    fn get_params(&self) -> Result<serde_json::Value, RevocationError> {
        convert_params(self.params.clone()).map_err(RevocationError::from)
    }

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}

impl BitstringStatusList {
    fn get_formatter_for_credential_format(
        &self,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format: String = self
            .params
            .bitstring_credential_format
            .clone()
            .unwrap_or_default()
            .into();

        self.formatter_provider
            .get_formatter(&format)
            .ok_or_else(|| RevocationError::FormatterNotFound(format.to_string()))
    }

    fn get_credential_index_on_revocation_list(
        &self,
        credentials_by_issuer_did: &[Credential],
        credential_id: &CredentialId,
        issuer_did_id: &DidId,
    ) -> Result<usize, RevocationError> {
        let index = credentials_by_issuer_did
            .iter()
            .position(|credential| credential.id == *credential_id)
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                *credential_id,
                *issuer_did_id,
            ))?;

        Ok(index)
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
        purpose: &str,
    ) -> Result<CredentialStatus, RevocationError> {
        create_credential_status(
            &self.core_base_url,
            revocation_list_id,
            index_on_status_list,
            purpose,
        )
    }

    async fn mark_credential_as_impl(
        &self,
        purpose: RevocationListPurpose,
        credential: &Credential,
        new_revocation_value: bool,
        data: CredentialAdditionalData,
    ) -> Result<RevocationUpdate, RevocationError> {
        let list_id = match purpose {
            RevocationListPurpose::Revocation => data.revocation_list_id,
            RevocationListPurpose::Suspension => data.suspension_list_id,
        };

        let issuer_did = credential
            .issuer_did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?
            .clone();

        let did_document = self
            .did_method_provider
            .resolve(&issuer_did.did.to_string().into())
            .await?;

        let assertion_methods =
            did_document
                .assertion_method
                .ok_or(RevocationError::MappingError(
                    "Missing assertion_method keys".to_owned(),
                ))?;

        let issuer_jwk_key_id = assertion_methods
            .first()
            .ok_or(RevocationError::MappingError(
                "Issuer has empty keys".to_owned(),
            ))
            .cloned()?;

        let encoded_list = generate_bitstring_from_credentials(
            &data.credentials_by_issuer_did,
            purpose_to_credential_state_enum(purpose.to_owned()),
            Some(BitstringCredentialInfo {
                credential_id: credential.id,
                value: new_revocation_value,
            }),
        )
        .await?;

        let list_credential = format_status_list_credential(
            &list_id,
            &issuer_did,
            encoded_list,
            purpose,
            &self.key_provider,
            &self.core_base_url,
            &*self.get_formatter_for_credential_format()?,
            issuer_jwk_key_id,
        )
        .await?;

        Ok(RevocationUpdate {
            status_type: self.get_status_type(),
            data: serde_json::to_vec(&RevocationUpdateData {
                id: list_id,
                value: list_credential.as_bytes().to_vec(),
            })?,
        })
    }
}

pub fn create_credential_status(
    core_base_url: &Option<String>,
    revocation_list_id: &RevocationListId,
    index_on_status_list: usize,
    purpose: &str,
) -> Result<CredentialStatus, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;
    Ok(CredentialStatus {
        id: Some(uuid::Uuid::new_v4().urn().to_string().parse().unwrap()),
        r#type: CREDENTIAL_STATUS_TYPE.to_string(),
        status_purpose: Some(purpose.to_string()),
        additional_fields: HashMap::from([
            (
                "statusListCredential".to_string(),
                revocation_list_url.into(),
            ),
            (
                "statusListIndex".to_string(),
                index_on_status_list.to_string().into(),
            ),
        ]),
    })
}

pub struct BitstringCredentialInfo {
    pub credential_id: CredentialId,
    pub value: bool,
}

pub fn purpose_to_credential_state_enum(purpose: RevocationListPurpose) -> CredentialStateEnum {
    match purpose {
        RevocationListPurpose::Revocation => CredentialStateEnum::Revoked,
        RevocationListPurpose::Suspension => CredentialStateEnum::Suspended,
    }
}

pub fn purpose_to_bitstring_status_purpose(purpose: RevocationListPurpose) -> StatusPurpose {
    match purpose {
        RevocationListPurpose::Revocation => StatusPurpose::Revocation,
        RevocationListPurpose::Suspension => StatusPurpose::Suspension,
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_did: &Did,
    encoded_list: String,
    purpose: RevocationListPurpose,
    key_provider: &Arc<dyn KeyProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
    key_id: String,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    let keys = issuer_did
        .keys
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "Issuer has no keys".to_string(),
        ))?;

    let key = keys
        .iter()
        .find(|k| k.role == KeyRole::AssertionMethod)
        .ok_or(RevocationError::KeyWithRoleNotFound(
            KeyRole::AssertionMethod,
        ))?;

    let auth_fn = key_provider.get_signature_provider(&key.key.to_owned(), Some(key_id))?;

    let status_list = formatter
        .format_bitstring_status_list(
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

pub async fn generate_bitstring_from_credentials(
    credentials_by_issuer_did: &[Credential],
    matching_state: CredentialStateEnum,
    additionally_changed_credential: Option<BitstringCredentialInfo>,
) -> Result<String, RevocationError> {
    let states = credentials_by_issuer_did
        .iter()
        .map(|credential| {
            if let Some(changed_credential) = additionally_changed_credential.as_ref() {
                if changed_credential.credential_id == credential.id {
                    return Ok(changed_credential.value);
                }
            }
            let states = credential
                .state
                .as_ref()
                .ok_or(RevocationError::MappingError("state is None".to_string()))?;
            let latest_state = states
                .first()
                .ok_or(RevocationError::MappingError(
                    "latest state not found".to_string(),
                ))?
                .state
                .to_owned();

            Ok(latest_state == matching_state)
        })
        .collect::<Result<Vec<_>, RevocationError>>()?;

    util::generate_bitstring(states).map_err(RevocationError::from)
}

pub fn get_revocation_list_url(
    revocation_list_id: &RevocationListId,
    core_base_url: &Option<String>,
) -> Result<String, RevocationError> {
    Ok(format!(
        "{}/ssi/revocation/v1/list/{}",
        core_base_url.as_ref().ok_or(RevocationError::MappingError(
            "Host URL not specified".to_string()
        ))?,
        revocation_list_id
    ))
}
