//! Bitstring Status List implementation.
//! https://www.w3.org/TR/vc-bitstring-status-list/

use std::collections::HashMap;
use std::sync::Arc;

use futures::FutureExt;
use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, RevocationListEntryId, RevocationListId};
use time::OffsetDateTime;
use uuid::Uuid;

use self::model::StatusPurpose;
use self::resolver::StatusListCachingLoader;
use crate::config::core_config::KeyAlgorithmType;
use crate::mapper::params::convert_params;
use crate::model::common::LockType;
use crate::model::credential::Credential;
use crate::model::did::{KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierType};
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListEntryStatus,
    RevocationListPurpose, StatusListCredentialFormat, StatusListType, UpdateRevocationListEntryId,
    UpdateRevocationListEntryRequest,
};
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{CredentialStatus, IdentifierDetails};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::VcdmCredential;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, JsonLdContext, Operation,
    RevocationMethodCapabilities, RevocationState,
};
use crate::provider::revocation::utils::status_purpose_to_revocation_state;
use crate::repository::error::DataLayerError;
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
    pub fn new(
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
            transaction_manager,
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
            self.create_credential_entry(
                credential.id,
                issuer_identifier,
                RevocationListPurpose::Revocation,
            )
            .await?,
        ];

        if credential_schema.allow_suspension {
            revocation_infos.push(
                self.create_credential_entry(
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
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .cloned()
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let purpose = if new_state == RevocationState::Revoked {
            RevocationListPurpose::Revocation
        } else {
            RevocationListPurpose::Suspension
        };

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

        self.revocation_list_repository
            .update_entry(
                UpdateRevocationListEntryId::Credential(credential.id),
                UpdateRevocationListEntryRequest {
                    status: Some(new_state.into()),
                },
            )
            .await?;

        let current_entries = self
            .revocation_list_repository
            .get_entries(current_list.id)
            .await?;

        let encoded_list = generate_bitstring_from_entries(current_entries, purpose).await?;

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

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        _issuer_details: &IdentifierDetails,
        _additional_credential_data: Option<CredentialDataByRole>,
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
            Ok(RevocationState::Valid)
        }
    }

    async fn add_issued_attestation(
        &self,
        _attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn get_attestation_revocation_info(
        &self,
        _key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn update_attestation_entries(
        &self,
        _keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        _new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Attestations not supported".to_string(),
        ))
    }

    async fn add_signature(
        &self,
        _signature_type: String,
        _issuer: &Identifier,
    ) -> Result<RevocationListEntryId, RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
    }

    async fn revoke_signature(
        &self,
        _signature_type: String,
        _signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        Err(RevocationError::OperationNotSupported(
            "Signatures not supported".to_string(),
        ))
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
        purpose: StatusPurpose,
    ) -> Result<CredentialStatus, RevocationError> {
        let revocation_list_url = get_revocation_list_url(revocation_list_id, &self.core_base_url)?;
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

    async fn create_credential_entry(
        &self,
        credential_id: CredentialId,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        let mut list_id = None;
        let mut index: Option<usize> = None;
        let tx_ok = self
            .transaction_manager
            .transaction(
                async {
                    let current_list = self
                        .revocation_list_repository
                        .get_revocation_by_issuer_identifier_id(
                            issuer_identifier.id,
                            purpose,
                            StatusListType::BitstringStatusList,
                            &Default::default(),
                        )
                        .await?;

                    list_id = Some(if let Some(current_list) = current_list {
                        current_list.id
                    } else {
                        let list_id = self
                            .start_new_list_for_credential(
                                credential_id,
                                issuer_identifier,
                                purpose,
                            )
                            .await?;
                        index = Some(0);
                        list_id
                    });

                    Ok(())
                }
                .boxed(),
            )
            .await
            .is_ok_and(|res| res.is_ok());

        if !tx_ok {
            list_id = None;
            index = None;
        }

        let list_id = if let Some(list_id) = list_id {
            list_id
        } else {
            // this means the transaction failed, and a new list was created in parallel
            // fetch the newly created list instead
            self.revocation_list_repository
                .get_revocation_by_issuer_identifier_id(
                    issuer_identifier.id,
                    purpose,
                    StatusListType::BitstringStatusList,
                    &Default::default(),
                )
                .await?
                .ok_or(RevocationError::MappingError(
                    "No revocation list found".to_string(),
                ))?
                .id
        };

        let index = if let Some(index) = index {
            index
        } else {
            self.add_credential_to_list(list_id, credential_id).await?
        };

        Ok(CredentialRevocationInfo {
            credential_status: self.create_credential_status(&list_id, index, purpose.into())?,
        })
    }

    async fn add_credential_to_list(
        &self,
        list_id: RevocationListId,
        credential_id: CredentialId,
    ) -> Result<usize, RevocationError> {
        let mut retry_counter = 0;
        loop {
            let result = self
                .transaction_manager
                .tx(async {
                    let index = self
                        .revocation_list_repository
                        .next_free_index(&list_id, Some(LockType::Update))
                        .await?;

                    match self
                        .revocation_list_repository
                        .create_entry(
                            list_id,
                            RevocationListEntityId::Credential(credential_id),
                            index,
                        )
                        .await
                    {
                        Ok(_) => Ok(Some(index)),
                        Err(DataLayerError::AlreadyExists) => {
                            tracing::info!("Retrying adding credential entry to list({list_id}), occupied index({index}), retry({retry_counter})");
                            Ok(None)
                        },
                        Err(e) => Err(e),
                    }
                }
                .boxed())
                .await??;

            if let Some(index) = result {
                return Ok(index);
            }

            if retry_counter > 100 {
                tracing::error!("Too many retries on revocation list: {list_id}");
                return Err(
                    DataLayerError::TransactionError("Too many retries".to_string()).into(),
                );
            }

            retry_counter += 1;
        }
    }

    async fn start_new_list_for_credential(
        &self,
        credential_id: CredentialId,
        issuer_identifier: &Identifier,
        purpose: RevocationListPurpose,
    ) -> Result<RevocationListId, RevocationError> {
        let revocation_list_id = Uuid::new_v4().into();
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
            .await?;

        self.revocation_list_repository
            .create_entry(
                revocation_list_id,
                RevocationListEntityId::Credential(credential_id),
                0,
            )
            .await?;

        Ok(revocation_list_id)
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
            purpose.into(),
            StatusListType::BitstringStatusList,
        )
        .await?;

    Ok(status_list)
}

async fn generate_bitstring_from_entries(
    entries: Vec<RevocationListEntry>,
    purpose: RevocationListPurpose,
) -> Result<String, RevocationError> {
    let states = entries
        .into_iter()
        .map(|entry| {
            (
                entry.index,
                get_revocation_entry_state(entry.status, purpose),
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

fn get_revocation_entry_state(
    entry_status: RevocationListEntryStatus,
    purpose: RevocationListPurpose,
) -> bool {
    match purpose {
        RevocationListPurpose::Revocation => entry_status == RevocationListEntryStatus::Revoked,
        RevocationListPurpose::Suspension => entry_status == RevocationListEntryStatus::Suspended,
        RevocationListPurpose::RevocationAndSuspension => matches!(
            entry_status,
            RevocationListEntryStatus::Revoked | RevocationListEntryStatus::Suspended
        ),
    }
}
