//! Bitstring Status List implementation.
//! https://www.w3.org/TR/vc-bitstring-status-list/

use std::collections::HashMap;
use std::sync::Arc;

use proc_macros::Provider;
use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::{
    RevocationListEntryId, RevocationListId, RevocationMethodId, SerializedCredential, SignerId,
};
use util::w3c_status_check;
use uuid::Uuid;

use self::model::StatusPurpose;
use self::resolver::StatusListCachingLoader;
use super::RevocationMethod;
use super::error::RevocationError;
use super::model::{
    CredentialDataByRole, CredentialRevocationInfo, Operation, ReservedEntries,
    RevocationMethodCapabilities, RevocationState,
};
use super::status_list::{StatusListSizeParams, add_entry_to_status_list};
use super::utils::status_purpose_to_revocation_state;
use crate::config::core_config::{KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::model::certificate::Certificate;
use crate::model::credential::Credential;
use crate::model::did::KeyRole;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::managed_instance_attestation::{
    ManagedInstanceAttestation, ManagedInstanceAttestationRevocationInfo,
};
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListEntryFilterValue,
    RevocationListEntryState, RevocationListPurpose, StatusListCredentialFormat,
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{
    CredentialStatus, IdentifierDetails, W3CCredentialStatus,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

pub mod model;
pub mod resolver;
pub mod util;

#[cfg(test)]
mod test;

const CREDENTIAL_STATUS_TYPE: &str = "BitstringStatusListEntry";

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde(default = "default_format")]
    pub format: StatusListCredentialFormat,

    #[serde(flatten)]
    pub size: StatusListSizeParams<
        // https://www.w3.org/TR/vc-bitstring-status-list/#revocation-bitstring-length
        131072,
    >,
}

fn default_format() -> StatusListCredentialFormat {
    StatusListCredentialFormat::Jwt
}

#[derive(Provider)]
pub struct BitstringStatusList {
    config_id: RevocationMethodId,
    core_base_url: Option<String>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    caching_loader: StatusListCachingLoader,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
    resolver: Arc<StatusListResolver>,
    params: Params,
}

impl BitstringStatusList {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        config_id: RevocationMethodId,
        core_base_url: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        caching_loader: StatusListCachingLoader,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
        client: Arc<dyn HttpClient>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        Ok(Self {
            config_id,
            core_base_url,
            key_algorithm_provider,
            did_method_provider,
            key_provider,
            caching_loader,
            formatter_provider,
            certificate_validator,
            revocation_list_repository,
            transaction_manager,
            resolver: Arc::new(StatusListResolver::new(client)),
            params,
        })
    }
}

#[async_trait::async_trait]
impl RevocationMethod for BitstringStatusList {
    fn can_check_status(&self, credential_status: &CredentialStatus) -> bool {
        let CredentialStatus::W3C(status) = credential_status else {
            return false;
        };

        status
            .iter()
            .all(|status| status.r#type == CREDENTIAL_STATUS_TYPE)
    }

    async fn reserve_credential_entries(
        &self,
        credential: &Credential,
    ) -> Result<ReservedEntries, RevocationError> {
        let issuer = credential.issuer()?.data;
        let issuer_identifier = issuer.identifier.as_ref().await?;

        let credential_schema = credential.common().schema.as_ref().await?;

        let mut purposes = vec![RevocationListPurpose::Revocation];
        if credential_schema.allow_suspension {
            purposes.push(RevocationListPurpose::Suspension);
        }

        let mut entry_ids = Vec::with_capacity(purposes.len());
        let mut statuses = Vec::with_capacity(purposes.len());
        for purpose in purposes {
            let (entry_id, status) = self.reserve_entry(&issuer_identifier, purpose).await?;
            entry_ids.push(entry_id);
            statuses.push(status);
        }

        Ok(ReservedEntries {
            entry_ids,
            revocation_info: CredentialRevocationInfo {
                credential_status: CredentialStatus::W3C(statuses),
                serial: None,
            },
        })
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        let issuer = credential.issuer()?.data;
        let issuer_identifier = issuer.identifier.as_ref().await?;

        let purpose = if new_state == RevocationState::Revoked {
            RevocationListPurpose::Revocation
        } else {
            RevocationListPurpose::Suspension
        };

        let current_list = self
            .revocation_list_repository
            .get_latest_list_by_issuer(
                issuer_identifier.id,
                issuer.certificate.as_ref().map(|c| c.id()),
                purpose,
                &self.config_id,
            )
            .await
            .error_while("getting revocation list")?
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                credential.common().id,
                issuer_identifier.id,
            ))?;

        self.revocation_list_repository
            .update_entry(
                UpdateRevocationListEntryId::Credential(credential.common().id),
                UpdateRevocationListEntryRequest {
                    state: Some(new_state.into()),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating revocation list entry")?;

        self.publish_list(current_list.id, &issuer_identifier, purpose)
            .await
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
        let CredentialStatus::W3C(status) = credential_status else {
            return Err(RevocationError::ValidationError(
                "Invalid credential status type".to_string(),
            ));
        };

        w3c_status_check(status, |status_entry| async move {
            self.check_status(status_entry, force_refresh).await
        })
        .await
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &ManagedInstanceAttestation,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &ManagedInstanceAttestationRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<ManagedInstanceAttestationRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn add_signature<'a>(
        &self,
        _signature_type: SignerId,
        _issuer: &'a Identifier,
        _certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn revoke_signature(
        &self,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn get_updated_list(
        &self,
        _list_id: RevocationListId,
    ) -> Result<Vec<u8>, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Updated list not supported".to_string(),
        ))
    }

    fn get_capabilities(&self) -> RevocationMethodCapabilities {
        RevocationMethodCapabilities {
            operations: vec![Operation::Revoke, Operation::Suspend],
        }
    }

    fn config_name(&self) -> &RevocationMethodId {
        &self.config_id
    }
}

impl BitstringStatusList {
    async fn get_formatter_for_issuance(
        &self,
        issuer_identifier: &Identifier,
    ) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let IdentifierData::Did(issuer_did) = &issuer_identifier.data else {
            return Err(RevocationError::MappingError(
                "issuer did is None".to_string(),
            ));
        };
        let issuer_did = issuer_did.as_ref().await?;

        let is_bbs = !issuer_did
            .keys
            .as_ref()
            .await?
            .into_iter()
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
            format => {
                return Err(RevocationError::FormatterNotFound(format.to_string()));
            }
        }
        .into();

        self.formatter_provider
            .get_credential_formatter(&format)
            .map_err(|_| RevocationError::FormatterNotFound(self.params.format.to_string()))
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
        }
        .to_string()
        .into();

        self.formatter_provider
            .get_credential_formatter(&format)
            .map_err(|_| RevocationError::FormatterNotFound(format.to_string()))
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
        purpose: StatusPurpose,
    ) -> Result<W3CCredentialStatus, RevocationError> {
        let revocation_list_url = get_revocation_list_url(revocation_list_id, &self.core_base_url)?;
        Ok(W3CCredentialStatus {
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

    /// Reserves an entry on the list of the given purpose, not linked to a credential yet
    async fn reserve_entry(
        &self,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<(RevocationListEntryId, W3CCredentialStatus), RevocationError> {
        let allocated = add_entry_to_status_list(
            RevocationListEntityId::Credential(None),
            issuer_identifier.id,
            None,
            purpose,
            &self.config_id,
            &self.params.size,
            self.transaction_manager.as_ref(),
            self.revocation_list_repository.as_ref(),
            async || self.prepare_empty_list(issuer_identifier, purpose).await,
        )
        .await?;

        Ok((
            allocated.entry_id,
            self.create_credential_status(&allocated.list_id, allocated.index, purpose.into())?,
        ))
    }

    async fn prepare_empty_list(
        &self,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<RevocationList, RevocationError> {
        let revocation_list_id = Uuid::new_v4().into();
        let formatted_list = format_status_list_credential(
            &revocation_list_id,
            issuer_identifier,
            util::generate_bitstring(vec![], self.params.size.capacity)
                .error_while("generating bitstring")?,
            purpose,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance(issuer_identifier).await?,
        )
        .await?;

        Ok(RevocationList {
            id: revocation_list_id,
            created_date: crate::clock::now_utc(),
            last_modified: crate::clock::now_utc(),
            formatted_list,
            format: self.params.format,
            r#type: self.config_id.to_owned(),
            purpose,
            issuer_identifier: issuer_identifier.to_owned().into(),
            issuer_certificate: None,
            sequence_number: 0,
        })
    }

    async fn publish_list(
        &self,
        list_id: RevocationListId,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<(), RevocationError> {
        let states = match purpose {
            RevocationListPurpose::Revocation => vec![RevocationListEntryState::Revoked],
            RevocationListPurpose::Suspension => vec![RevocationListEntryState::Suspended],
            RevocationListPurpose::RevocationAndSuspension => vec![
                RevocationListEntryState::Revoked,
                RevocationListEntryState::Suspended,
            ],
        };
        let entries = self
            .revocation_list_repository
            .get_entries(ListQuery {
                include_count: false,
                filtering: Some(
                    RevocationListEntryFilterValue::List(list_id).condition()
                        & RevocationListEntryFilterValue::States(states),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting revocation list entries")?
            .values;

        let encoded_list =
            generate_bitstring_from_entries(entries, self.params.size.capacity).await?;

        let formatted_list = format_status_list_credential(
            &list_id,
            issuer_identifier,
            encoded_list,
            purpose,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance(issuer_identifier).await?,
        )
        .await?;

        self.revocation_list_repository
            .update_formatted_list(&list_id, formatted_list)
            .await
            .error_while("updating revocation list")?;

        Ok(())
    }

    async fn check_status(
        &self,
        credential_status: &W3CCredentialStatus,
        force_refresh: bool,
    ) -> Result<RevocationState, RevocationError> {
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
            .await
            .error_while("getting bitstring status list")?;

        let response: StatusListCacheEntry = serde_json::from_slice(content)?;
        let response_content: SerializedCredential = String::from_utf8(response.content)?.into();

        let is_bbs =
            if let Ok(vcdm) = serde_json::from_str::<VcdmCredential>(response_content.as_ref()) {
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
            .extract_credentials(&response_content, None, key_verification)
            .await
            .error_while("parsing status list")?;

        let encoded_list = status_credential
            .claims
            .get("encodedList")
            .and_then(|value| value.value.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing encodedList in status credential".to_string(),
            ))?;

        if util::extract_bitstring_index(encoded_list.to_owned(), list_index)
            .error_while("extracting bitstring index")?
        {
            status_purpose_to_revocation_state(credential_status.status_purpose.as_ref())
        } else {
            Ok(RevocationState::Valid)
        }
    }
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_identifier: &Identifier,
    encoded_list: String,
    purpose: RevocationListPurpose,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
) -> Result<Vec<u8>, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    if !matches!(issuer_identifier.data, IdentifierData::Did(_)) {
        return Err(RevocationError::InvalidIdentifierType(
            issuer_identifier.data.r#type(),
        ));
    }

    let selection = issuer_identifier
        .select_key(KeySelection {
            key: KeyFilter::did_role(KeyRole::AssertionMethod),
            ..Default::default()
        })
        .await
        .error_while("selecting key")?;

    let key = selection.key();
    let key_id = if let SelectedKey::Did {
        did,
        key: related_key,
    } = &selection
    {
        Some(did.verification_method_id(related_key))
    } else {
        None
    };

    let auth_fn =
        key_provider.get_signature_provider(key, key_id, key_algorithm_provider.clone())?;

    let status_list = formatter
        .format_status_list(
            revocation_list_url,
            selection,
            encoded_list,
            auth_fn,
            purpose.into(),
            RevocationType::BitstringStatusList,
        )
        .await
        .error_while("formatting status list")?;

    Ok(status_list)
}

async fn generate_bitstring_from_entries(
    entries: Vec<RevocationListEntry>,
    capacity: usize,
) -> Result<String, RevocationError> {
    let states = entries
        .into_iter()
        .map(|entry| {
            entry.index.ok_or(RevocationError::MappingError(
                "revocation list entry index missing".to_string(),
            ))
        })
        .collect::<Result<_, _>>()?;

    Ok(util::generate_bitstring(states, capacity).error_while("generating bitstring")?)
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
