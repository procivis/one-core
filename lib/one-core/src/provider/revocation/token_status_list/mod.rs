//! Token Status List implementation.
//! https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list-03

use std::collections::HashMap;
use std::sync::Arc;

use coset::iana::{CwtClaimName, EnumI64};
use coset::{AsCborValue, TaggedCborSerializable};
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use futures::FutureExt;
use one_dto_mapper::convert_inner;
use proc_macros::Provider;
use rcgen::KeyUsagePurpose;
use resolver::{StatusListCacheEntry, StatusListResolver};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::{RevocationListEntryId, RevocationListId, RevocationMethodId, SignerId};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use self::resolver::StatusListCachingLoader;
use self::util::calculate_preferred_token_size;
use crate::config::core_config::{FormatType, RevocationType};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::x509::{pem_chain_into_x5c, x5c_into_pem_chain};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::common::LockType;
use crate::model::credential::Credential;
use crate::model::did::KeyRole;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::managed_instance_attested_key::{
    ManagedInstanceAttestedKey, ManagedInstanceAttestedKeyRevocationInfo,
};
use crate::model::relation::Related;
use crate::model::revocation_list::{
    RevocationList, RevocationListEntityId, RevocationListEntry, RevocationListEntryState,
    RevocationListPurpose, StatusListCredentialFormat, UpdateRevocationListEntryId,
    UpdateRevocationListEntryRequest,
};
use crate::proto::certificate_validator::{
    CertSelection, CertificateValidationOptions, CertificateValidator, EnforceKeyUsage,
};
use crate::proto::cose::CoseSign1;
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::TransactionManager;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::jwt_formatter::model::{
    TokenStatusListContent, TokenStatusListSubject,
};
use crate::provider::credential_formatter::mdoc_formatter::util::{
    StatusListEncoded, extract_certificate_from_x5chain_header,
};
use crate::provider::credential_formatter::model::{
    CredentialStatus, IdentifierDetails, TokenVerifier,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::sdjwtvc_formatter::model::SdJwtVcStatus;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::presentation_formatter::mso_mdoc::try_verify_cose_sign1;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::{
    CredentialDataByRole, CredentialRevocationInfo, Operation, RevocationMethodCapabilities,
    RevocationState,
};
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::managed_instance_repository::ManagedInstanceRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};
use crate::validator::{
    validate_expiration_time, validate_issuance_time, validate_not_before_time,
};

pub mod resolver;
pub mod util;

#[cfg(test)]
mod test;

pub(crate) const URI_KEY: &str = "uri";
pub(crate) const INDEX_KEY: &str = "idx";
pub(crate) const CERTIFICATE_KEY: &str = "certificate";
const CREDENTIAL_STATUS_TYPE: &str = "TokenStatusListEntry";

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Params {
    #[serde(default = "default_format")]
    pub format: StatusListCredentialFormat,
    #[serde(default = "default_operations")]
    pub operations: Vec<Operation>,
    #[serde_as(as = "DurationSeconds<i64>")]
    #[serde(default = "default_1_minute")]
    leeway_seconds: Duration,
}

fn default_format() -> StatusListCredentialFormat {
    StatusListCredentialFormat::Jwt
}

fn default_operations() -> Vec<Operation> {
    vec![Operation::Revoke, Operation::Suspend]
}

pub(super) fn default_1_minute() -> Duration {
    Duration::minutes(1)
}

#[derive(Provider)]
pub struct TokenStatusList {
    config_id: RevocationMethodId,
    core_base_url: Option<String>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_provider: Arc<dyn KeyProvider>,
    caching_loader: StatusListCachingLoader,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    http_client: Arc<dyn HttpClient>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    wallet_unit_repository: Arc<dyn ManagedInstanceRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    transaction_manager: Arc<dyn TransactionManager>,
    resolver: Arc<StatusListResolver>,
    params: Params,
}

impl TokenStatusList {
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
        http_client: Arc<dyn HttpClient>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        wallet_unit_repository: Arc<dyn ManagedInstanceRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        transaction_manager: Arc<dyn TransactionManager>,
        client: Arc<dyn HttpClient>,
        params: serde_json::Value,
    ) -> Result<Self, InitializationError> {
        let params: Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        if ![
            StatusListCredentialFormat::Jwt,
            StatusListCredentialFormat::Cwt,
        ]
        .contains(&params.format)
        {
            return Err(RevocationError::ValidationError(
                "TokenStatusList revocation format must be JWT or CWT".to_string(),
            )
            .error_while("validating config")
            .into());
        }

        if !params.operations.contains(&Operation::Revoke) {
            return Err(RevocationError::ValidationError(
                "TokenStatusList does not support suspension only".to_string(),
            )
            .error_while("validating config")
            .into());
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
            http_client,
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
        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer identifier is None".to_string(),
            ))?
            .as_ref()
            .await?;

        let issuer_certificate = if matches!(issuer_identifier.data, IdentifierData::Certificate(_))
        {
            let certificate =
                credential
                    .issuer_certificate
                    .as_ref()
                    .ok_or(RevocationError::MappingError(
                        "issuer certificate is None".to_string(),
                    ))?;
            Some(certificate.as_ref().await?.to_owned())
        } else {
            None
        };

        let entry = self
            .create_entry(
                RevocationListEntityId::Credential(credential.id),
                &issuer_identifier,
                issuer_certificate.as_ref(),
            )
            .await?;

        Ok(vec![entry.1])
    }

    async fn mark_credential_as(
        &self,
        credential: &Credential,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .ok_or(RevocationError::MappingError(
                "issuer identifier is None".to_string(),
            ))?
            .as_ref()
            .await?;

        let issuer_certificate = if matches!(issuer_identifier.data, IdentifierData::Certificate(_))
        {
            let certificate =
                credential
                    .issuer_certificate
                    .as_ref()
                    .ok_or(RevocationError::MappingError(
                        "issuer certificate is None".to_string(),
                    ))?;
            Some(certificate.as_ref().await?.to_owned())
        } else {
            None
        };

        let current_list = self
            .revocation_list_repository
            .get_revocation_by_issuer_identifier_id(
                issuer_identifier.id,
                issuer_certificate.as_ref().map(|c| c.id),
                self.purpose()?,
                &self.config_id,
            )
            .await
            .error_while("getting revocation list")?
            .ok_or(RevocationError::MissingCredentialIndexOnRevocationList(
                credential.id,
                issuer_identifier.id,
            ))?;

        self.revocation_list_repository
            .update_entry(
                UpdateRevocationListEntryId::Credential(credential.id),
                UpdateRevocationListEntryRequest {
                    state: Some(new_state.into()),
                },
            )
            .await
            .error_while("updating revocation list entry")?;

        let current_entries = self
            .revocation_list_repository
            .get_entries(current_list.id)
            .await
            .error_while("getting revocation list entries")?;

        let encoded_list =
            generate_token_from_entries(current_entries, self.required_bits()?).await?;

        let formatted_list = format_status_list_credential(
            &current_list.id,
            &issuer_identifier,
            issuer_certificate.as_ref(),
            encoded_list,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance()?,
            self.purpose()?,
        )
        .await?;

        self.revocation_list_repository
            .update_formatted_list(&current_list.id, formatted_list)
            .await
            .error_while("updating revocation list")?;

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

        let (content, _) = &self
            .caching_loader
            .get(list_url, self.resolver.clone(), force_refresh)
            .await
            .error_while("getting token status list")?;

        let response: StatusListCacheEntry = serde_json::from_slice(content)?;

        let status_list = if response.content_type == "application/statuslist+cwt" {
            let ca_certificate = credential_status
                .additional_fields
                .get(CERTIFICATE_KEY)
                .and_then(|index| index.as_str())
                .map(ToString::to_string);

            self.extract_info_from_list_credential_cwt(
                response.content,
                issuer_details,
                ca_certificate,
                list_url,
            )
            .await?
        } else {
            let response_content = String::from_utf8(response.content)?;
            self.extract_info_from_list_credential_jwt(&response_content, issuer_details)
                .await?
        };

        Ok(util::extract_state_from_token(&status_list, list_index)
            .error_while("extracting token status")?)
    }

    async fn add_issued_attestation(
        &self,
        attestation: &ManagedInstanceAttestedKey,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        let wallet_instance = self
            .wallet_unit_repository
            .get(&attestation.instance_id)
            .await
            .error_while("getting wallet instance")?;

        let issuer_id = wallet_instance
            .organisation
            .as_ref()
            .await?
            .wallet_provider_issuer
            .ok_or(RevocationError::MappingError(
                "Missing wallet_provider_issuer".to_string(),
            ))?;

        let issuer_identifier = self
            .identifier_repository
            .get(issuer_id)
            .await
            .error_while("getting identifier")?;

        let issuer_certificate = if let IdentifierData::Certificate(certificates)
        | IdentifierData::CertificateAuthority(certificates) =
            &issuer_identifier.data
        {
            certificates
                .as_ref()
                .await?
                .iter()
                .find(|c| c.state == CertificateState::Active)
                .cloned()
        } else {
            None
        };

        let result = self
            .create_entry(
                RevocationListEntityId::WalletUnitAttestedKey(attestation.id),
                &issuer_identifier,
                issuer_certificate.as_ref(),
            )
            .await?;
        Ok(result.1)
    }

    async fn get_attestation_revocation_info(
        &self,
        key_info: &ManagedInstanceAttestedKeyRevocationInfo,
    ) -> Result<CredentialRevocationInfo, RevocationError> {
        Ok(CredentialRevocationInfo {
            credential_status: self.create_credential_status(
                &key_info.revocation_list.id(),
                key_info.revocation_list_index,
            )?,
            serial: None,
        })
    }

    async fn update_attestation_entries(
        &self,
        keys: Vec<ManagedInstanceAttestedKeyRevocationInfo>,
        new_state: RevocationState,
    ) -> Result<(), RevocationError> {
        let mut revocation_lists: HashMap<RevocationListId, (Related<RevocationList>, Vec<usize>)> =
            HashMap::new();
        for key in keys {
            revocation_lists
                .entry(key.revocation_list.id())
                .or_insert((key.revocation_list, vec![]))
                .1
                .push(key.revocation_list_index);
        }

        self.transaction_manager
            .tx(async move {
                for (list, indexes) in revocation_lists.into_values() {
                    let list = list.as_ref().await?;
                    for index in indexes {
                        self.revocation_list_repository
                            .update_entry(
                                UpdateRevocationListEntryId::Index(list.id, index),
                                UpdateRevocationListEntryRequest {
                                    state: Some(new_state.into()),
                                },
                            )
                            .await
                            .error_while("updating revocation list entry")?;
                    }

                    let entries = self
                        .revocation_list_repository
                        .get_entries(list.id)
                        .await
                        .error_while("getting revocation list entries")?;

                    let encoded_list =
                        generate_token_from_entries(entries, self.required_bits()?).await?;

                    let issuer_certificate = match list.issuer_certificate.as_ref() {
                        None => None,
                        Some(certificate) => Some(certificate.as_ref().await?.to_owned()),
                    };
                    let formatted_list = format_status_list_credential(
                        &list.id,
                        list.issuer_identifier.as_ref().await?.as_ref(),
                        issuer_certificate.as_ref(),
                        encoded_list,
                        &*self.key_provider,
                        &self.key_algorithm_provider,
                        &self.core_base_url,
                        &*self.get_formatter_for_issuance()?,
                        self.purpose()?,
                    )
                    .await?;

                    self.revocation_list_repository
                        .update_formatted_list(&list.id, formatted_list)
                        .await
                        .error_while("updating revocation list")?;
                }
                Ok::<_, RevocationError>(())
            }
            .boxed())
            .await
            .error_while("updating attestations")??;

        Ok(())
    }

    async fn add_signature<'a>(
        &self,
        signature_type: SignerId,
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
                            state: Some(RevocationListEntryState::Revoked),
                        },
                    )
                    .await
                    .error_while("updating revocation list entry")?;

                let current_list = self
                    .revocation_list_repository
                    .get_revocation_list_by_entry_id(signature_id)
                    .await
                    .error_while("getting revocation list")?;
                let current_entries = self
                    .revocation_list_repository
                    .get_entries(current_list.id)
                    .await
                    .error_while("getting revocation list entries")?;

                let encoded_list =
                    generate_token_from_entries(current_entries, self.required_bits()?).await?;

                let issuer_certificate = match current_list.issuer_certificate.as_ref() {
                    None => None,
                    Some(certificate) => Some(certificate.as_ref().await?.to_owned()),
                };
                let formatted_list = format_status_list_credential(
                    &current_list.id,
                    current_list.issuer_identifier.as_ref().await?.as_ref(),
                    issuer_certificate.as_ref(),
                    encoded_list,
                    &*self.key_provider,
                    &self.key_algorithm_provider,
                    &self.core_base_url,
                    &*self.get_formatter_for_issuance()?,
                    self.purpose()?,
                )
                .await?;

                self.revocation_list_repository
                    .update_formatted_list(&current_list.id, formatted_list)
                    .await
                    .error_while("updating revocation list")?;

                Ok::<_, RevocationError>(())
            }
            .boxed())
            .await
            .error_while("revoking signature")?
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
            operations: self.params.operations.clone(),
        }
    }

    fn config_name(&self) -> &RevocationMethodId {
        &self.config_id
    }
}

impl TokenStatusList {
    fn get_formatter_for_issuance(&self) -> Result<Arc<dyn CredentialFormatter>, RevocationError> {
        let format_type = match self.params.format {
            StatusListCredentialFormat::Jwt => FormatType::Jwt,
            StatusListCredentialFormat::Cwt => FormatType::Mdoc,
            format => {
                return Err(RevocationError::ValidationError(format!(
                    "Invalid revocation list format: {format}"
                )));
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
        let purpose = self.purpose()?;
        let maybe_list_and_entry_id = self
            .transaction_manager
            .tx(async {
                let current_list = self
                    .revocation_list_repository
                    .get_revocation_by_issuer_identifier_id(
                        issuer_identifier.id,
                        issuer_certificate.map(|c| c.id),
                        purpose,
                        &self.config_id,
                    )
                    .await
                    .error_while("getting revocation list")?;

                Ok(match current_list {
                    Some(list) => (list.id, None),
                    None => {
                        let (new_list_id, new_entry_id) = self
                            .start_new_list_for_entity(
                                entity_id.clone(),
                                issuer_identifier,
                                issuer_certificate,
                            )
                            .await
                            .error_while("starting new token status list")?;
                        (new_list_id, Some(new_entry_id))
                    }
                })
            }
            .boxed())
            .await
            .error_while("finding revocation list")
            .flatten();

        let (list_id, maybe_entry_id) = match maybe_list_and_entry_id {
            Ok((list_id, maybe_entry_id)) => (list_id, maybe_entry_id),
            Err(error) if error.error_code() == ErrorCode::BR_0357 => {
                // this means the transaction failed, and a new list was created in parallel
                // fetch the newly created list instead
                (
                    self.revocation_list_repository
                        .get_revocation_by_issuer_identifier_id(
                            issuer_identifier.id,
                            issuer_certificate.map(|c| c.id),
                            purpose,
                            &self.config_id,
                        )
                        .await
                        .error_while("getting revocation list")?
                        .ok_or(RevocationError::MappingError(
                            "No revocation list found".to_string(),
                        ))?
                        .id,
                    None,
                )
            }
            Err(e) => {
                return Err(e.into());
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
                .await;
            let Ok(result) = result else {
                tracing::debug!(
                    "Transaction failed adding entity to list({list_id}), retry({retry_counter})"
                );
                continue;
            };

            if let Some(index) = result.error_while("adding entity to list")? {
                return Ok(index);
            }

            if retry_counter > 100 {
                tracing::error!("Too many retries on revocation list: {list_id}");
                return Err(
                    DataLayerError::TransactionError("Too many retries".to_string())
                        .error_while("adding revocation list entry")
                        .into(),
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
        let formatted_list = format_status_list_credential(
            &revocation_list_id,
            issuer_identifier,
            issuer_certificate,
            generate_token_from_entries(vec![], self.required_bits()?).await?,
            &*self.key_provider,
            &self.key_algorithm_provider,
            &self.core_base_url,
            &*self.get_formatter_for_issuance()?,
            self.purpose()?,
        )
        .await?;

        self.revocation_list_repository
            .create_revocation_list(RevocationList {
                id: revocation_list_id,
                created_date: crate::clock::now_utc(),
                last_modified: crate::clock::now_utc(),
                formatted_list,
                format: self.params.format,
                r#type: self.config_id.to_owned(),
                purpose: self.purpose()?,
                issuer_identifier: issuer_identifier.to_owned().into(),
                issuer_certificate: convert_inner(issuer_certificate.cloned()),
            })
            .await
            .error_while("creating revocation list")?;

        let entry_id = self
            .revocation_list_repository
            .create_entry(revocation_list_id, entity_id, Some(0))
            .await
            .error_while("creating revocation list entry")?;

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

    fn purpose(&self) -> Result<RevocationListPurpose, RevocationError> {
        let operations = &self.params.operations;
        Ok(
            match (
                operations.contains(&Operation::Revoke),
                operations.contains(&Operation::Suspend),
            ) {
                (true, true) => RevocationListPurpose::RevocationAndSuspension,
                (true, false) => RevocationListPurpose::Revocation,
                (false, _) => {
                    return Err(RevocationError::ValidationError(
                        "Invalid operations defined".to_string(),
                    ));
                }
            },
        )
    }

    fn required_bits(&self) -> Result<usize, RevocationError> {
        Ok(
            if self.purpose()? == RevocationListPurpose::RevocationAndSuspension {
                2
            } else {
                1
            },
        )
    }

    async fn extract_info_from_list_credential_jwt(
        &self,
        jwt: &str,
        issuer_details: &IdentifierDetails,
    ) -> Result<TokenStatusListSubject, RevocationError> {
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
            Jwt::build_from_token(jwt, Some(&key_verification), issuer_did)
                .await
                .error_while("validating token status list")?;

        Ok(jwt.payload.custom.status_list)
    }

    async fn extract_info_from_list_credential_cwt(
        &self,
        cwt: Vec<u8>,
        credential_issuer_details: &IdentifierDetails,
        ca_certificate: Option<String>,
        list_url: &str,
    ) -> Result<TokenStatusListSubject, RevocationError> {
        let cose_sign1 = CoseSign1(coset::CoseSign1::from_tagged_slice(cwt.as_slice())?);

        let cwt_certificate_details = extract_certificate_from_x5chain_header(
            self.certificate_validator.as_ref(),
            self.http_client.as_ref(),
            &cose_sign1,
            true,
        )
        .await
        .error_while("extracting certificate")?;

        let key_verification = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        };

        let x5c = pem_chain_into_x5c(&cwt_certificate_details.chain)
            .error_while("converting PEM chain")?;
        try_verify_cose_sign1(&cose_sign1, &x5c, &key_verification)
            .await
            .error_while("verifying cwt")?;

        let ca_pem_chain = if let Some(ca_certificate) = ca_certificate {
            Some(ca_certificate)
        } else {
            let IdentifierDetails::Certificate(credential_issuer_certificate) =
                credential_issuer_details
            else {
                return Err(RevocationError::ValidationError(
                    "invalid issuer type".to_string(),
                ));
            };

            if credential_issuer_certificate.chain == cwt_certificate_details.chain {
                // CWT issued by the same certificate, skipping consistency check
                None
            } else {
                let mut x5c = pem_chain_into_x5c(&credential_issuer_certificate.chain)
                    .error_while("converting PEM chain")?;
                if x5c.len() < 2 {
                    // this is a valid case, the IACA certificate is not contained in the MDOC credential
                    // but then we cannot validate consistency of the CWT issuer
                    tracing::warn!("missing CA certificate in chain");
                    None
                } else {
                    // remove the leaf certificate and keep the rest of the CA chain
                    x5c.remove(0);
                    Some(x5c_into_pem_chain(&x5c).error_while("converting x5c")?)
                }
            }
        };
        if let Some(ca_pem_chain) = ca_pem_chain {
            self.certificate_validator
                .validate_chain_against_ca_chain(
                    &cwt_certificate_details.chain,
                    &ca_pem_chain,
                    CertificateValidationOptions::signature_and_revocation(Some(vec![
                        EnforceKeyUsage::DigitalSignature,
                    ])),
                    CertSelection::Leaf,
                )
                .await
                .error_while("checking CA chain")?;
        }

        let payload = cose_sign1
            .0
            .payload
            .ok_or(RevocationError::ValidationError(
                "missing CWT payload".to_string(),
            ))?;

        let payload: ciborium::Value = ciborium::from_reader(payload.as_slice())?;
        let payload = payload.as_map().ok_or(RevocationError::ValidationError(
            "invalid CWT payload".to_string(),
        ))?;
        let get_payload_field = |index: i64| {
            let index = ciborium::Value::Integer(index.into());
            payload.iter().find_map(|(k, v)| (k == &index).then_some(v))
        };

        let subject = get_payload_field(CwtClaimName::Sub.to_i64());
        if subject
            .and_then(|subject| subject.as_text())
            .is_none_or(|subject| subject != list_url)
        {
            return Err(RevocationError::ValidationError(format!(
                "Invalid subject: `{subject:?}`",
            )));
        }

        let issued_at = get_payload_field(CwtClaimName::Iat.to_i64());
        validate_issuance_time(&timestamp_to_time(issued_at)?, self.params.leeway_seconds)
            .error_while("checking validity")?;

        let not_before = get_payload_field(CwtClaimName::Nbf.to_i64());
        validate_not_before_time(&timestamp_to_time(not_before)?, self.params.leeway_seconds)
            .error_while("checking validity")?;

        let expires_at = get_payload_field(CwtClaimName::Exp.to_i64());
        validate_expiration_time(&timestamp_to_time(expires_at)?, self.params.leeway_seconds)
            .error_while("checking validity")?;

        let status_list: StatusListEncoded = get_payload_field(65533)
            .ok_or(RevocationError::ValidationError(
                "missing CWT status list".to_string(),
            ))?
            .deserialized()?;

        Ok(TokenStatusListSubject {
            bits: status_list.bits as _,
            value: Base64UrlSafeNoPadding::encode_to_string(status_list.list.0)?,
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
    purpose: RevocationListPurpose,
) -> Result<Vec<u8>, RevocationError> {
    let revocation_list_url = get_revocation_list_url(revocation_list_id, core_base_url)?;

    if matches!(
        issuer_identifier.data,
        IdentifierData::CertificateAuthority(_)
    ) {
        return Err(RevocationError::InvalidIdentifierType(
            issuer_identifier.data.r#type(),
        ));
    }

    let selection = issuer_identifier
        .select_key(KeySelection {
            certificate: CertificateFilter::key_usage(vec![KeyUsagePurpose::DigitalSignature])
                .and_id(issuer_certificate.map(|c| c.id))
                .allow_all_states(),
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

    let algorithm = key
        .key_algorithm_type()
        .error_while("getting key algorithm type")?;

    let status_list = formatter
        .format_status_list(
            revocation_list_url,
            selection,
            encoded_list,
            algorithm,
            auth_fn,
            purpose.into(),
            RevocationType::TokenStatusList,
        )
        .await
        .error_while("formatting token status list")?;

    Ok(status_list)
}

async fn generate_token_from_entries(
    entries: Vec<RevocationListEntry>,
    bits: usize,
) -> Result<String, RevocationError> {
    let index_states = entries
        .into_iter()
        .map(|entry| {
            Ok((
                entry.index.ok_or(RevocationError::MappingError(
                    "revocation list entry index missing".to_string(),
                ))?,
                entry.state,
            ))
        })
        .collect::<Result<Vec<_>, RevocationError>>()?;

    let preferred_token_size = calculate_preferred_token_size(index_states.len(), bits);
    Ok(
        util::generate_token(index_states, bits, preferred_token_size)
            .error_while("generating token status list")?,
    )
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

fn timestamp_to_time(
    timestamp: Option<&ciborium::Value>,
) -> Result<Option<OffsetDateTime>, RevocationError> {
    use coset::cwt::Timestamp;

    let Some(timestamp) = timestamp else {
        return Ok(None);
    };

    let unix_timestamp = match Timestamp::from_cbor_value(timestamp.to_owned())? {
        Timestamp::WholeSeconds(unix_timestamp) => unix_timestamp,
        Timestamp::FractionalSeconds(fractional) => fractional as i64,
    };

    Ok(Some(
        OffsetDateTime::from_unix_timestamp(unix_timestamp)
            .map_err(|e| RevocationError::ValidationError(format!("Invalid timestamp: {e}")))?,
    ))
}
