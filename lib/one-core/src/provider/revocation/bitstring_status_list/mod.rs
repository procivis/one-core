//! Bitstring Status List implementation.
//! https://www.w3.org/TR/vc-bitstring-status-list/

use std::collections::HashMap;
use std::sync::Arc;

use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::Identifier;
use crate::model::revocation_list::{
    RevocationListPurpose, StatusListCredentialFormat, StatusListType,
};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, IssuerDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::model::{
    RevocationUpdateData, StatusPurpose,
};
use crate::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialAdditionalData, CredentialDataByRole, CredentialRevocationInfo,
    CredentialRevocationState, JsonLdContext, Operation, RevocationListId,
    RevocationMethodCapabilities, RevocationUpdate,
};
use crate::provider::revocation::utils::status_purpose_to_revocation_state;
use crate::service::certificate::validator::CertificateValidator;
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
    pub format: StatusListCredentialFormat,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            format: StatusListCredentialFormat::Jwt,
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
    pub certificate_validator: Arc<dyn CertificateValidator>,
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
        certificate_validator: Arc<dyn CertificateValidator>,
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
            certificate_validator,
            resolver: Arc::new(StatusListResolver::new(client)),
            params: params.unwrap_or(Params {
                format: StatusListCredentialFormat::Jwt,
            }),
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
            .issuer_identifier
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer identifier is None".to_string(),
            ))?
            .did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "credential schema is None".to_string(),
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
                    data.suspension_list_id
                        .as_ref()
                        .ok_or(RevocationError::MappingError(
                            "suspension id is None".to_string(),
                        ))?,
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
        _issuer_details: &IssuerDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
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

        let (content, media_type) = &self
            .caching_loader
            .get(list_url, self.resolver.clone(), force_refresh)
            .await?;

        let response: StatusListCacheEntry = serde_json::from_slice(content)?;
        let response_content = String::from_utf8(response.content)?;

        let is_bbs = if let Ok(vcdm) = serde_json::from_str::<VcdmCredential>(&response_content) {
            vcdm.proof
                .is_some_and(|proof| proof.cryptosuite == "bbs-2023")
        } else {
            false
        };

        let content_type = match (media_type, &response.content_type) {
            (Some(media_type), _) => media_type,
            (None, Some(content_type)) => content_type,
            _ => {
                return Err(RevocationError::ValidationError(
                    "Missing content type".to_string(),
                ));
            }
        };

        let key_verification = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        let status_credential = self
            .get_formatter_for_parsing(content_type, is_bbs)?
            .extract_credentials(&response_content, None, key_verification, None)
            .await?;

        let encoded_list = status_credential
            .claims
            .claims
            .get("encodedList")
            .and_then(|value| value.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing encodedList in status credential".to_string(),
            ))?;

        if util::extract_bitstring_index(encoded_list.to_owned(), list_index)? {
            status_purpose_to_revocation_state(credential_status.status_purpose.as_ref())
        } else {
            Ok(CredentialRevocationState::Valid)
        }
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke, Operation::Suspend],
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
    fn get_formatter_for_issuance(
        &self,
        is_bbs: bool,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format = match self.params.format {
            StatusListCredentialFormat::Jwt => self.params.format.to_string(),
            StatusListCredentialFormat::JsonLdClassic => {
                if is_bbs {
                    "JSON_LD_BBSPLUS".to_string()
                } else {
                    self.params.format.to_string()
                }
            }
        };

        self.formatter_provider
            .get_formatter(format.as_str())
            .ok_or_else(|| RevocationError::FormatterNotFound(self.params.format.to_string()))
    }

    fn get_formatter_for_parsing(
        &self,
        content_type: &str,
        is_bbs: bool,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format = match content_type {
            "application/jwt" => "JWT",
            "application/vc+ld+json" | "application/ld+json" | "application/json" => {
                if is_bbs {
                    "JSON_LD_BBSPLUS"
                } else {
                    "JSON_LD_CLASSIC"
                }
            }
            _ => {
                return Err(RevocationError::MappingError(format!(
                    "Invalid status list Content-Type: {content_type}"
                )));
            }
        };

        self.formatter_provider
            .get_formatter(format)
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
            RevocationListPurpose::Suspension => {
                data.suspension_list_id
                    .ok_or(RevocationError::MappingError(
                        "suspension_list_id is None".to_string(),
                    ))?
            }
        };

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .cloned()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let issuer_did = issuer_identifier
            .did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?
            .clone();

        let did_document = self.did_method_provider.resolve(&issuer_did.did).await?;

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

        let is_bbs = !issuer_did
            .keys
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer_did keys are None".to_string(),
            ))?
            .iter()
            .any(|key| key.key.key_type == KeyAlgorithmType::BbsPlus.to_string());

        let list_credential = format_status_list_credential(
            &list_id,
            StatusListType::BitstringStatusList,
            &issuer_identifier,
            encoded_list,
            purpose,
            &self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance(is_bbs)?,
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
        id: Some(
            uuid::Uuid::new_v4()
                .urn()
                .to_string()
                .parse()
                .map_err(|e| {
                    RevocationError::ValidationError(format!("Failed to parse URL: `{e}`"))
                })?,
        ),
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
    status_list_type: StatusListType,
    issuer_identifier: &Identifier,
    encoded_list: String,
    purpose: RevocationListPurpose,
    key_provider: &Arc<dyn KeyProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
    key_id: String,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    let key = issuer_identifier
        .find_matching_key(&KeyFilter::role_filter(KeyRole::AssertionMethod))
        .map_err(|_| RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod))?
        .ok_or(RevocationError::KeyWithRoleNotFound(
            KeyRole::AssertionMethod,
        ))?;

    let auth_fn =
        key_provider.get_signature_provider(key, Some(key_id), key_algorithm_provider.clone())?;

    let algorithm_type = key
        .key_algorithm_type()
        .ok_or(FormatterError::CouldNotFormat(format!(
            "Unsupported algorithm: {}",
            key.key_type
        )))?;

    let status_list = formatter
        .format_status_list(
            revocation_list_url,
            issuer_identifier,
            encoded_list,
            algorithm_type,
            auth_fn,
            purpose_to_bitstring_status_purpose(purpose),
            status_list_type,
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
            let state = credential.state;

            Ok(state == matching_state)
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
