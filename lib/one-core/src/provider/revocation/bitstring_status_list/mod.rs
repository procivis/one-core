//! Bitstring Status List implementation.
//! https://www.w3.org/TR/vc-bitstring-status-list/

use std::collections::HashMap;
use std::sync::Arc;

use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::CredentialId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::mapper::params::convert_params;
use crate::model::credential::{Credential, CredentialStateEnum};
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::revocation_list::{
    RevocationList, RevocationListCredentialEntry, RevocationListPurpose,
    StatusListCredentialFormat, StatusListType,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::bitstring_status_list::resolver::StatusListCachingLoader;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, CredentialRevocationState, JsonLdContext,
    Operation, RevocationListId, RevocationMethodCapabilities,
};
use crate::provider::revocation::utils::status_purpose_to_revocation_state;
use crate::repository::revocation_list_repository::RevocationListRepository;

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
    pub revocation_list_repository: Arc<dyn RevocationListRepository>,
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
        revocation_list_repository: Arc<dyn RevocationListRepository>,
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
            revocation_list_repository,
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
    ) -> Result<Vec<CredentialRevocationInfo>, RevocationError> {
        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "credential schema is None".to_string(),
            ))?;

        let mut revocation_infos = vec![
            self.put_credential_on_list(
                credential.id,
                issuer_identifier,
                RevocationListPurpose::Revocation,
            )
            .await?,
        ];

        if credential_schema.allow_suspension {
            revocation_infos.push(
                self.put_credential_on_list(
                    credential.id,
                    issuer_identifier,
                    RevocationListPurpose::Suspension,
                )
                .await?,
            );
        }

        Ok(revocation_infos)
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: CredentialRevocationState,
    ) -> Result<(), RevocationError> {
        match new_state {
            CredentialRevocationState::Revoked => {
                self.mark_credential(RevocationListPurpose::Revocation, credential, true)
                    .await
            }
            CredentialRevocationState::Valid => {
                self.mark_credential(RevocationListPurpose::Suspension, credential, false)
                    .await
            }
            CredentialRevocationState::Suspended { .. } => {
                self.mark_credential(RevocationListPurpose::Suspension, credential, true)
                    .await
            }
        }
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
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
            .and_then(|value| value.value.as_str())
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
        issuer_identifier: &Identifier,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let issuer_did = issuer_identifier
            .did
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ))?;

        let is_bbs = !issuer_did
            .keys
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer_did keys are None".to_string(),
            ))?
            .iter()
            .any(|key| key.key.key_type == KeyAlgorithmType::BbsPlus.to_string());

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
            .get_credential_formatter(format.as_str())
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
            .get_credential_formatter(format)
            .ok_or_else(|| RevocationError::FormatterNotFound(format.to_string()))
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

    async fn mark_credential(
        &self,
        purpose: RevocationListPurpose,
        credential: &Credential,
        new_revocation_value: bool,
    ) -> Result<(), RevocationError> {
        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .cloned()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let current_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier.id,
                purpose,
                StatusListType::BitstringStatusList,
                &Default::default(),
            )
            .await?
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                credential.id,
                issuer_identifier.id,
            ))?;

        let current_credential_states = self
            .revocation_list_repository
            .get_linked_credentials(current_list.id)
            .await?;

        let encoded_list = generate_bitstring_from_credentials(
            &current_credential_states,
            purpose,
            Some(BitstringCredentialInfo {
                credential_id: credential.id,
                value: new_revocation_value,
            }),
        )
        .await?;

        let list_credential = format_status_list_credential(
            &current_list.id,
            &issuer_identifier,
            encoded_list,
            purpose,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance(&issuer_identifier)?,
        )
        .await?;

        self.revocation_list_repository
            .update_credentials(&current_list.id, list_credential.into_bytes())
            .await?;

        Ok(())
    }

    async fn put_credential_on_list(
        &self,
        credential_id: CredentialId,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        let current_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier.id,
                purpose,
                StatusListType::BitstringStatusList,
                &Default::default(),
            )
            .await?;

        let mut index_on_status_list = 0;

        let list_id = if let Some(current_list) = &current_list {
            index_on_status_list = 1 + self
                .revocation_list_repository
                .get_max_used_index(&current_list.id)
                .await?
                .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                    credential_id,
                    issuer_identifier.id,
                ))?;

            current_list.id
        } else {
            // Create a new list

            let revocation_list_id = Uuid::new_v4();
            let list_credential = format_status_list_credential(
                &revocation_list_id,
                issuer_identifier,
                util::generate_bitstring(vec![])?,
                purpose,
                &*self.key_provider,
                &self.key_algorithm_provider,
                &self.core_base_url,
                &*self.get_formatter_for_issuance(issuer_identifier)?,
            )
            .await?;

            self.revocation_list_repository
                .create_revocation_list(RevocationList {
                    id: revocation_list_id,
                    created_date: OffsetDateTime::now_utc(),
                    last_modified: OffsetDateTime::now_utc(),
                    credentials: list_credential.into_bytes(),
                    format: self.params.format,
                    r#type: StatusListType::BitstringStatusList,
                    purpose,
                    issuer_identifier: Some(issuer_identifier.to_owned()),
                })
                .await?
        };

        self.revocation_list_repository
            .create_credential_entry(list_id, credential_id, index_on_status_list)
            .await?;

        Ok(CredentialRevocationInfo {
            credential_status: self.create_credential_status(
                &list_id,
                index_on_status_list,
                match purpose {
                    RevocationListPurpose::Revocation => "revocation",
                    RevocationListPurpose::Suspension => "suspension",
                },
            )?,
        })
    }
}

pub(crate) fn create_credential_status(
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

struct BitstringCredentialInfo {
    pub credential_id: CredentialId,
    pub value: bool,
}

fn purpose_to_bitstring_status_purpose(purpose: RevocationListPurpose) -> StatusPurpose {
    match purpose {
        RevocationListPurpose::Revocation => StatusPurpose::Revocation,
        RevocationListPurpose::Suspension => StatusPurpose::Suspension,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_identifier: &Identifier,
    encoded_list: String,
    purpose: RevocationListPurpose,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    if issuer_identifier.r#type != IdentifierType::Did {
        return Err(FormatterError::CouldNotFormat(format!(
            "Unsupported identifier type: {}",
            issuer_identifier.r#type
        ))
        .into());
    }

    let issuer_did = issuer_identifier
        .did
        .as_ref()
        .ok_or(RevocationError::MappingError(
            "issuer did is None".to_string(),
        ))?
        .clone();

    let key = issuer_did
        .find_first_matching_key(&KeyFilter::role_filter(KeyRole::AssertionMethod))
        .map_err(|_| RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod))?
        .ok_or(RevocationError::KeyWithRoleNotFound(
            KeyRole::AssertionMethod,
        ))?;

    let key_id = issuer_did.verification_method_id(key);
    let key = &key.key;

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
            StatusListType::BitstringStatusList,
        )
        .await?;

    Ok(status_list)
}

async fn generate_bitstring_from_credentials(
    credentials: &[RevocationListCredentialEntry],
    purpose: RevocationListPurpose,
    additionally_changed_credential: Option<BitstringCredentialInfo>,
) -> Result<String, RevocationError> {
    let states = credentials
        .iter()
        .map(|entry| {
            if let Some(changed_credential) = additionally_changed_credential.as_ref()
                && changed_credential.credential_id == entry.credential_id
            {
                return (entry.index, changed_credential.value);
            }

            (
                entry.index,
                match purpose {
                    RevocationListPurpose::Suspension => {
                        entry.state == CredentialStateEnum::Suspended
                    }
                    RevocationListPurpose::Revocation => matches!(
                        entry.state,
                        CredentialStateEnum::Revoked
                            | CredentialStateEnum::Rejected
                            | CredentialStateEnum::Error // also mark failed credentials as revoked to prevent misuse
                    ),
                },
            )
        })
        .collect::<Vec<_>>();

    util::generate_bitstring(states).map_err(RevocationError::from)
}

fn get_revocation_list_url(
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
