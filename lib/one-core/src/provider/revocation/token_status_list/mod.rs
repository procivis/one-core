//! Token Status List implementation.
//! https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use futures::FutureExt;
use itertools::Itertools;
use rcgen::KeyUsagePurpose;
use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId};
use time::OffsetDateTime;
use uuid::Uuid;

use self::resolver::StatusListCachingLoader;
use self::util::{PREFERRED_ENTRY_SIZE, calculate_preferred_token_size};
use crate::config::core_config::{FormatType, RevocationType};
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::model::common::LockType;
use crate::model::credential::Credential;
use crate::model::did::{DidRelations, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierType};
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListEntryStatus,
    RevocationListPurpose, RevocationListRelations, StatusListCredentialFormat,
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use crate::model::wallet_unit::WalletUnitRelations;
use crate::model::wallet_unit_attested_key::{
    WalletUnitAttestedKey, WalletUnitAttestedKeyRevocationInfo,
};
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListContent;
use crate::provider::credential_formatter::model::{
    CredentialStatus, IdentifierDetails, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::bitstring_status_list::model::StatusPurpose;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, JsonLdContext, Operation,
    RevocationMethodCapabilities, RevocationState,
};
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::wallet_unit_repository::WalletUnitRepository;
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

pub mod resolver;
pub mod util;

#[cfg(test)]
mod test;

pub(crate) const URI_KEY: &str = "uri";
pub(crate) const INDEX_KEY: &str = "idx";
const CREDENTIAL_STATUS_TYPE: &str = "TokenStatusListEntry";

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

pub struct TokenStatusList {
    config_id: RevocationMethodId,
    core_base_url: Option<String>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    caching_loader: StatusListCachingLoader,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    wallet_unit_repository: Arc<dyn WalletUnitRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
    resolver: Arc<StatusListResolver>,
    params: Params,
}

impl TokenStatusList {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        config_id: RevocationMethodId,
        core_base_url: Option<String>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_provider: Arc<dyn KeyProvider>,
        caching_loader: StatusListCachingLoader,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        wallet_unit_repository: Arc<dyn WalletUnitRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
        client: Arc<dyn HttpClient>,
        params: Option<Params>,
    ) -> Result<Self, RevocationError> {
        let params = params.unwrap_or_default();

        if params.format != StatusListCredentialFormat::Jwt {
            return Err(RevocationError::ValidationError(
                "Token revocation format must be JWT".to_string(),
            ));
        }

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
            wallet_unit_repository,
            identifier_repository,
            transaction_manager,
            resolver: Arc::new(StatusListResolver::new(client)),
            params,
        })
    }
}

#[async_trait::async_trait]
impl RevocationMethod for TokenStatusList {
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

        let issuer_certificate =
            if issuer_identifier.r#type == IdentifierType::Certificate {
                Some(credential.issuer_certificate.as_ref().ok_or(
                    RevocationError::MappingError("issuer certificate is None".to_string()),
                )?)
            } else {
                None
            };

        let entry = self
            .create_entry(
                RevocationListEntityId::Credential(credential.id),
                issuer_identifier,
                issuer_certificate,
            )
            .await?;

        Ok(vec![entry.1])
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
                .ok_or(RevocationError::MappingError(
                    "issuer identifier is None".to_string(),
                ))?;

        let issuer_certificate =
            if issuer_identifier.r#type == IdentifierType::Certificate {
                Some(credential.issuer_certificate.as_ref().ok_or(
                    RevocationError::MappingError("issuer certificate is None".to_string()),
                )?)
            } else {
                None
            };

        let current_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier.id,
                issuer_certificate.map(|c| c.id),
                RevocationListPurpose::RevocationAndSuspension,
                &self.config_id,
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

        let encoded_list = generate_token_from_entries(current_entries).await?;

        let list_credential = format_status_list_credential(
            &current_list.id,
            issuer_identifier,
            issuer_certificate,
            encoded_list,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance()?,
        )
        .await?;

        self.revocation_list_repository
            .update_formatted_list(&current_list.id, list_credential.into_bytes())
            .await?;

        Ok(())
    }

    async fn check_credential_revocation_status(
        &self,
        credential_status: &CredentialStatus,
        issuer_details: &IdentifierDetails,
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
            .get(URI_KEY)
            .and_then(|url| url.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list url".to_string(),
            ))?;

        let list_index = credential_status
            .additional_fields
            .get(INDEX_KEY)
            .and_then(|index| index.as_str())
            .ok_or(RevocationError::ValidationError(
                "Missing status list index".to_string(),
            ))?;
        let list_index: usize = list_index
            .parse()
            .map_err(|_| RevocationError::ValidationError("Invalid list index".to_string()))?;

        let (content, _media_type) = &self
            .caching_loader
            .get(list_url, self.resolver.clone(), force_refresh)
            .await?;

        let response: StatusListCacheEntry = serde_json::from_slice(content)?;

        let response_content = String::from_utf8(response.content)?;
        let key_verification: Box<dyn TokenVerifier> = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });

        // TODO: ONE-6158 validate issuer certificate/CA of status-list is trusted

        let issuer_did = if let IdentifierDetails::Did(issuer_did) = issuer_details {
            Some(issuer_did.to_owned())
        } else {
            None
        };

        let jwt: Jwt<TokenStatusListContent> =
            Jwt::build_from_token(&response_content, Some(&key_verification), issuer_did).await?;

        Ok(util::extract_state_from_token(
            &jwt.payload.custom.status_list,
            list_index,
        )?)
    }

    async fn add_issued_attestation(
        &self,
        attestation: &WalletUnitAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        let wallet_unit = self
            .wallet_unit_repository
            .get_wallet_unit(
                &attestation.wallet_unit_id,
                &WalletUnitRelations {
                    organisation: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(RevocationError::MappingError(
                "Missing wallet unit".to_string(),
            ))?;

        let issuer_id = wallet_unit
            .organisation
            .ok_or(RevocationError::MappingError(
                "Missing organisation".to_string(),
            ))?
            .wallet_provider_issuer
            .ok_or(RevocationError::MappingError(
                "Missing wallet_provider_issuer".to_string(),
            ))?;

        let issuer_identifier = self
            .identifier_repository
            .get(
                issuer_id,
                &IdentifierRelations {
                    organisation: None,
                    did: Some(DidRelations {
                        keys: Some(Default::default()),
                        ..Default::default()
                    }),
                    key: Some(Default::default()),
                    certificates: Some(CertificateRelations {
                        key: Some(Default::default()),
                        ..Default::default()
                    }),
                },
            )
            .await?
            .ok_or(RevocationError::MappingError(
                "Missing issuer_identifier".to_string(),
            ))?;

        let issuer_certificate = if let Some(certificates) = &issuer_identifier.certificates {
            certificates
                .iter()
                .find(|c| c.state == CertificateState::Active)
        } else {
            None
        };

        let result = self
            .create_entry(
                RevocationListEntityId::WalletUnitAttestedKey(attestation.id),
                &issuer_identifier,
                issuer_certificate,
            )
            .await?;
        Ok(result.1)
    }

    async fn get_attestation_revocation_info(
        &self,
        key_info: &WalletUnitAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Ok(CredentialRevocationInfo {
            credential_status: self.create_credential_status(
                &key_info.revocation_list.id,
                key_info.revocation_list_index,
            )?,
            serial: None,
        })
    }

    async fn update_attestation_entries(
        &self,
        keys: Vec<WalletUnitAttestedKeyRevocationInfo>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        struct RevocationListKey(RevocationList);
        impl Hash for RevocationListKey {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.0.id.hash(state);
            }
        }
        impl PartialEq for RevocationListKey {
            fn eq(&self, other: &Self) -> bool {
                self.0.id == other.0.id
            }
        }
        impl Eq for RevocationListKey {}

        let revocation_lists = keys
            .into_iter()
            .map(|k| {
                (
                    RevocationListKey(k.revocation_list),
                    k.revocation_list_index,
                )
            })
            .into_group_map();

        self.transaction_manager
            .tx(async move {
                for (RevocationListKey(list), indexes) in revocation_lists.into_iter() {
                    for index in indexes {
                        self.revocation_list_repository
                            .update_entry(
                                UpdateRevocationListEntryId::Index(list.id, index),
                                UpdateRevocationListEntryRequest {
                                    status: Some(new_state.clone().into()),
                                },
                            )
                            .await?;
                    }

                    let entries = self.revocation_list_repository.get_entries(list.id).await?;

                    let encoded_list = generate_token_from_entries(entries).await?;

                    let list_credential = format_status_list_credential(
                        &list.id,
                        &list.issuer_identifier.ok_or(RevocationError::MappingError(
                            "Missing issuer_identifier".to_string(),
                        ))?,
                        list.issuer_certificate.as_ref(),
                        encoded_list,
                        &*self.key_provider,
                        &self.key_algorithm_provider,
                        &self.core_base_url,
                        &*self.get_formatter_for_issuance()?,
                    )
                    .await?;

                    self.revocation_list_repository
                        .update_formatted_list(&list.id, list_credential.into_bytes())
                        .await?;
                }
                Ok::<_, RevocationError>(())
            }
            .boxed())
            .await??;

        Ok(())
    }

    async fn add_signature<'a>(
        &self,
        signature_type: String,
        issuer: &'a Identifier,
        certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        let result = self
            .create_entry(
                RevocationListEntityId::Signature(signature_type, None),
                issuer,
                certificate,
            )
            .await?;

        Ok(result)
    }

    async fn revoke_signature(
        &self,
        signature_id: RevocationListEntryId,
    ) -> Result<(), RevocationError> {
        self.transaction_manager
            .tx(async move {
                self.revocation_list_repository
                    .update_entry(
                        UpdateRevocationListEntryId::Id(signature_id),
                        UpdateRevocationListEntryRequest {
                            status: Some(RevocationListEntryStatus::Revoked),
                        },
                    )
                    .await?;

                let current_list = self
                    .revocation_list_repository
                    .get_revocation_list_by_entry_id(
                        signature_id,
                        &RevocationListRelations {
                            issuer_identifier: Some(IdentifierRelations {
                                certificates: Some(CertificateRelations {
                                    key: Some(Default::default()),
                                    ..Default::default()
                                }),
                                did: Some(DidRelations {
                                    keys: Some(Default::default()),
                                    ..Default::default()
                                }),
                                key: Some(Default::default()),
                                ..Default::default()
                            }),
                            issuer_certificate: Some(Default::default()),
                        },
                    )
                    .await?
                    .ok_or(RevocationError::MappingError(
                        "Missing list for revocation entry".to_owned(),
                    ))?;
                let issuer =
                    current_list
                        .issuer_identifier
                        .ok_or(RevocationError::MappingError(
                            "Missing revocation list issuer".to_owned(),
                        ))?;

                let current_entries = self
                    .revocation_list_repository
                    .get_entries(current_list.id)
                    .await?;

                let encoded_list = generate_token_from_entries(current_entries).await?;

                let list_credential = format_status_list_credential(
                    &current_list.id,
                    &issuer,
                    current_list.issuer_certificate.as_ref(),
                    encoded_list,
                    &*self.key_provider,
                    &self.key_algorithm_provider,
                    &self.core_base_url,
                    &*self.get_formatter_for_issuance()?,
                )
                .await?;

                self.revocation_list_repository
                    .update_formatted_list(&current_list.id, list_credential.into_bytes())
                    .await?;

                Ok::<_, RevocationError>(())
            }
            .boxed())
            .await?
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

    fn get_json_ld_context(&self) -> Result<JsonLdContext, RevocationError> {
        Ok(JsonLdContext::default())
    }
}

impl TokenStatusList {
    fn get_formatter_for_issuance(&self) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format_type = match self.params.format {
            StatusListCredentialFormat::Jwt => FormatType::Jwt,
            StatusListCredentialFormat::JsonLdClassic => FormatType::JsonLdClassic,
            format => {
                return Err(RevocationError::FormatterNotFound(format.to_string()));
            }
        };
        self.formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or(RevocationError::FormatterNotFound(format_type.to_string()))
            .map(|(_, formatter)| formatter)
    }

    async fn create_entry<'a>(
        &self,
        entity_id: RevocationListEntityId,
        issuer_identifier: &'a Identifier,
        issuer_certificate: Option<&'a Certificate>,
    ) -> Result<(RevocationListEntryId, CredentialRevocationInfo), RevocationError> {
        let maybe_list_and_entry_id = self
            .transaction_manager
            .tx(async {
                let current_list = self
                    .revocation_list_repository
                    .get_revocation_by_issuer_identifier_id(
                        issuer_identifier.id,
                        issuer_certificate.map(|c| c.id),
                        RevocationListPurpose::RevocationAndSuspension,
                        &self.config_id,
                        &Default::default(),
                    )
                    .await?;

                Ok(match current_list {
                    Some(list) => (list.id, None),
                    None => {
                        let (new_list_id, new_entry_id) = self
                            .start_new_list_for_entity(
                                entity_id.clone(),
                                issuer_identifier,
                                issuer_certificate,
                            )
                            .await?;
                        (new_list_id, Some(new_entry_id))
                    }
                })
            }
            .boxed())
            .await
            .map_err(|e| e.into())
            .flatten();

        let (list_id, maybe_entry_id) = match maybe_list_and_entry_id {
            Ok((list_id, maybe_entry_id)) => (list_id, maybe_entry_id),
            Err(RevocationError::DataLayerError(DataLayerError::AlreadyExists)) => {
                // this means the transaction failed, and a new list was created in parallel
                // fetch the newly created list instead
                (
                    self.revocation_list_repository
                        .get_revocation_by_issuer_identifier_id(
                            issuer_identifier.id,
                            issuer_certificate.map(|c| c.id),
                            RevocationListPurpose::RevocationAndSuspension,
                            &self.config_id,
                            &Default::default(),
                        )
                        .await?
                        .ok_or(RevocationError::MappingError(
                            "No revocation list found".to_string(),
                        ))?
                        .id,
                    None,
                )
            }
            Err(e) => {
                return Err(e);
            }
        };

        let (entry_id, entry_index) = match maybe_entry_id {
            Some(entry_id) => (entry_id, 0),
            None => self.add_entity_to_list(list_id, entity_id).await?,
        };

        let revocation_info = CredentialRevocationInfo {
            credential_status: self.create_credential_status(&list_id, entry_index)?,
            serial: None,
        };
        Ok((entry_id, revocation_info))
    }

    async fn add_entity_to_list(
        &self,
        list_id: RevocationListId,
        entity_id: RevocationListEntityId,
    ) -> Result<(RevocationListEntryId, usize), RevocationError> {
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
                        .create_entry(list_id, entity_id.to_owned(), Some(index))
                        .await
                    {
                        Ok(entry_id) => Ok(Some((entry_id, index))),
                        Err(DataLayerError::AlreadyExists) => {
                            tracing::info!(
                                "Retrying adding entity to list({list_id}), occupied index({index}), retry({retry_counter})"
                            );
                            Ok(None)
                        }
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

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn start_new_list_for_entity(
        &self,
        entity_id: RevocationListEntityId,
        issuer_identifier: &Identifier,
        issuer_certificate: Option<&Certificate>,
    ) -> Result<(RevocationListId, RevocationListEntryId), RevocationError> {
        let revocation_list_id = Uuid::new_v4().into();
        let list_credential = format_status_list_credential(
            &revocation_list_id,
            issuer_identifier,
            issuer_certificate,
            generate_token_from_entries(vec![]).await?,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance()?,
        )
        .await?;

        self.revocation_list_repository
            .create_revocation_list(RevocationList {
                id: revocation_list_id,
                created_date: OffsetDateTime::now_utc(),
                last_modified: OffsetDateTime::now_utc(),
                formatted_list: list_credential.into_bytes(),
                format: self.params.format,
                r#type: self.config_id.to_owned(),
                purpose: RevocationListPurpose::RevocationAndSuspension,
                issuer_identifier: Some(issuer_identifier.to_owned()),
                issuer_certificate: issuer_certificate.cloned(),
            })
            .await?;

        let entry_id = self
            .revocation_list_repository
            .create_entry(revocation_list_id, entity_id, Some(0))
            .await?;

        Ok((revocation_list_id, entry_id))
    }

    fn create_credential_status(
        &self,
        revocation_list_id: &RevocationListId,
        index_on_status_list: usize,
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
            status_purpose: Some("revocation".to_string()),
            additional_fields: HashMap::from([
                (URI_KEY.to_string(), revocation_list_url.into()),
                (
                    INDEX_KEY.to_string(),
                    index_on_status_list.to_string().into(),
                ),
            ]),
        })
    }
}

pub(crate) fn credential_status_from_sdjwt_status(
    sd_jwt_status: &Option<SdJwtVcStatus>,
) -> Vec<CredentialStatus> {
    match sd_jwt_status {
        None => vec![],
        Some(value) => {
            vec![CredentialStatus {
                id: None,
                r#type: CREDENTIAL_STATUS_TYPE.to_string(),
                status_purpose: Some("revocation".to_string()),
                additional_fields: HashMap::from([
                    (
                        URI_KEY.to_string(),
                        serde_json::Value::String(value.status_list.uri.to_string()),
                    ),
                    (
                        INDEX_KEY.to_string(),
                        serde_json::Value::String(value.status_list.index.to_string()),
                    ),
                ]),
            }]
        }
    }
}

#[expect(clippy::too_many_arguments)]
#[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
async fn format_status_list_credential(
    revocation_list_id: &RevocationListId,
    issuer_identifier: &Identifier,
    issuer_certificate: Option<&Certificate>,
    encoded_list: String,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    core_base_url: &Option<String>,
    formatter: &dyn CredentialFormatter,
) -> Result<String, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    let selection = issuer_identifier
        .select_key(KeySelection {
            certificate: issuer_certificate.map(|c| c.id),
            key_filter: Some(KeyFilter {
                did_role: Some(KeyRole::AssertionMethod),
                certificate_key_usage: Some(vec![KeyUsagePurpose::DigitalSignature]),
                ..Default::default()
            }),
            ..Default::default()
        })
        .map_err(|_| RevocationError::KeyWithRoleNotFound(KeyRole::AssertionMethod))?;
    let key = selection.key();

    let key_id = if let SelectedKey::Did { did, key } = selection {
        Some(did.verification_method_id(key))
    } else {
        None
    };

    let auth_fn =
        key_provider.get_signature_provider(key, key_id, key_algorithm_provider.clone())?;

    let algorithm = key
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
            algorithm,
            auth_fn,
            StatusPurpose::Revocation,
            RevocationType::TokenStatusList,
        )
        .await?;

    Ok(status_list)
}

async fn generate_token_from_entries(
    entries: Vec<RevocationListEntry>,
) -> Result<String, RevocationError> {
    let index_states = entries
        .into_iter()
        .map(|entry| {
            Ok((
                entry.index.ok_or(RevocationError::MappingError(
                    "revocation list entry index missing".to_string(),
                ))?,
                entry.status,
            ))
        })
        .collect::<Result<Vec<_>, RevocationError>>()?;

    let preferred_token_size =
        calculate_preferred_token_size(index_states.len(), PREFERRED_ENTRY_SIZE);
    util::generate_token(index_states, PREFERRED_ENTRY_SIZE, preferred_token_size)
        .map_err(RevocationError::from)
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
