use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::FutureExt;
use itertools::Itertools;
use shared_types::{
    BlobId, CertificateId, IdentifierId, IdentifierTrustInformationId, KeyId, OrganisationId,
    TrustCollectionId,
};
use time::OffsetDateTime;
use tracing::warn;
use url::Url;
use uuid::Uuid;

use super::IdentifierService;
use super::dto::{
    CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateIdentifierTrustInformationRequestDTO, GetIdentifierListResponseDTO,
    GetIdentifierResponseDTO, IdentifierFilterParamsDTO, PatchIdentifierRequestDTO,
    ResolveTrustEntriesRequestDTO, ResolvedTrustEntriesResponseDTO, ResolvedTrustEntryResponseDTO,
};
use super::error::IdentifierServiceError;
use super::mapper::{
    identifier_to_response_dto, identifiers_to_list_response_dto, params_to_query,
    to_create_did_request,
};
use super::validator::validate_identifier_type;
use crate::config::core_config;
use crate::config::core_config::BlobStorageType;
use crate::error::{ContextWithErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::blob::{Blob, UpdateBlobRequest};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::ecosystem::EcosystemOutcomes;
use crate::model::identifier::{
    Identifier, IdentifierData, IdentifierFilterValue, IdentifierListIncludeEntity,
    IdentifierListQuery, IdentifierState, IdentifierType, SortableIdentifierColumn,
    UpdateIdentifierRequest,
};
use crate::model::identifier_trust_information::IdentifierTrustInformation;
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::trust_collection::{
    TrustCollection, TrustCollectionFilterValue, TrustCollectionListQuery,
};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
};
use crate::proto::identifier_creator::{
    self, CreateLocalIdentifierRequestParams, CreateLocalIdentifierRequestType, IdentifierName,
    RemoteIdentifierOutcome, build_identifier_translations,
};
use crate::proto::transaction_manager::IsolationLevel;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::model::TrustInformationInput;
use crate::provider::trust_list_subscriber::{
    Feature, TrustEntityResponse, TrustListSubscriber, TrustListSubscriberCapabilities,
};
use crate::repository::error::{DataLayerError, EntityKind};
use crate::service::certificate::dto::CreateCertificateRequestDTO;
use crate::service::common_dto::ListQueryDTO;
use crate::service::error::ValidationError;
use crate::service::identifier::dto::{
    CreateCertificateAuthorityRequestDTO, CreateRemoteIdentifierRequestDTO,
    ResolvedTrustEntrySourceResponseDTO,
};
use crate::validator::throw_if_org_id_not_matching_session;

impl IdentifierService {
    /// Returns details of an identifier
    ///
    /// # Arguments
    ///
    /// * `id` - Identifier uuid
    pub async fn get_identifier(
        &self,
        id: &IdentifierId,
    ) -> Result<GetIdentifierResponseDTO, IdentifierServiceError> {
        let identifier =
            self.identifier_repository
                .get(*id)
                .await
                .map_err(|error| match error {
                    DataLayerError::EntityNotFound { .. } => IdentifierServiceError::NotFound(*id),
                    error => error.error_while("getting identifier").into(),
                })?;

        if identifier.deleted_at.is_some() {
            return Err(IdentifierServiceError::NotFound(*id));
        }

        throw_if_org_id_not_matching_session(
            &identifier.organisation.id(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        identifier_to_response_dto(
            identifier,
            &*self.blob_storage_provider,
            &self.config.global_settings.default_language,
        )
        .await
    }

    /// Returns list of identifiers according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_identifier_list(
        &self,
        filter_params: ListQueryDTO<
            SortableIdentifierColumn,
            IdentifierFilterParamsDTO,
            IdentifierListIncludeEntity,
        >,
    ) -> Result<GetIdentifierListResponseDTO, IdentifierServiceError> {
        throw_if_org_id_not_matching_session(
            &filter_params.filter.organisation_id,
            &*self.session_provider,
        )
        .error_while("checking session")?;
        let includes = filter_params.include.clone().unwrap_or_default();
        let query = params_to_query(
            filter_params,
            &*self.credential_schema_repository,
            &*self.proof_schema_repository,
            &*self.ecosystem_provider,
            &self.config,
        )
        .await?;
        let list_response = self
            .identifier_repository
            .get_identifier_list(query)
            .await
            .and_then(|list| list.require_count())
            .error_while("getting identifiers")?;

        identifiers_to_list_response_dto(
            list_response,
            &*self.blob_storage_provider,
            &includes,
            &self.config.global_settings.default_language,
        )
        .await
    }

    /// Creates a remote identifier from a DID, JWK, or certificate / CA chain(s).
    pub async fn create_remote_identifier(
        &self,
        request: CreateRemoteIdentifierRequestDTO,
    ) -> Result<IdentifierId, IdentifierServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(IdentifierServiceError::OrganisationDeactivated(
                request.organisation_id,
            ));
        }

        if let Some(existing) = self
            .find_identifier_by_name(&request.name, organisation.id)
            .await?
        {
            return Err(IdentifierServiceError::RemoteIdentifierAlreadyExists(
                existing.id,
            ));
        }

        let outcome = match (
            request.did,
            request.key,
            request.certificates,
            request.certificate_authorities,
        ) {
            (Some(did), None, None, None) => {
                validate_identifier_type(
                    core_config::IdentifierType::Did,
                    &self.config.identifier,
                )?;
                self.create_remote_from_details(
                    organisation.id,
                    IdentifierDetails::Did(did),
                    request.name,
                )
                .await?
            }
            (None, Some(key), None, None) => {
                validate_identifier_type(
                    core_config::IdentifierType::Key,
                    &self.config.identifier,
                )?;
                self.create_remote_from_details(
                    organisation.id,
                    IdentifierDetails::Key(key),
                    request.name,
                )
                .await?
            }
            (None, None, Some(chains), None) if !chains.is_empty() => {
                validate_identifier_type(
                    core_config::IdentifierType::Certificate,
                    &self.config.identifier,
                )?;
                self.identifier_creator
                    .create_remote_certificate_identifier(
                        request.organisation_id,
                        request.name,
                        chains.into_iter().map(|c| c.chain).collect(),
                        IdentifierType::Certificate,
                    )
                    .await
                    .error_while("creating remote certificate identifier")?
            }
            (None, None, None, Some(chains)) if !chains.is_empty() => {
                validate_identifier_type(
                    core_config::IdentifierType::CertificateAuthority,
                    &self.config.identifier,
                )?;
                self.identifier_creator
                    .create_remote_certificate_identifier(
                        request.organisation_id,
                        request.name,
                        chains.into_iter().map(|c| c.chain).collect(),
                        IdentifierType::CertificateAuthority,
                    )
                    .await
                    .error_while("creating remote CA identifier")?
            }
            _ => return Err(IdentifierServiceError::InvalidCreationInput),
        };

        match outcome {
            RemoteIdentifierOutcome::Created(id) => {
                tracing::info!("Created remote identifier `{id}`");
                Ok(id)
            }
            RemoteIdentifierOutcome::AlreadyExists(id) => {
                Err(IdentifierServiceError::RemoteIdentifierAlreadyExists(id))
            }
        }
    }

    async fn find_identifier_by_name(
        &self,
        name: &str,
        organisation_id: shared_types::OrganisationId,
    ) -> Result<Option<Identifier>, IdentifierServiceError> {
        let list = self
            .identifier_repository
            .get_identifier_list(IdentifierListQuery {
                include_count: false,
                filtering: Some(
                    IdentifierFilterValue::Name(StringMatch::equals(name)).condition()
                        & IdentifierFilterValue::OrganisationId(organisation_id).condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("looking up identifier by name")?;
        Ok(list.values.into_iter().next())
    }

    async fn create_remote_from_details(
        &self,
        organisation_id: OrganisationId,
        details: IdentifierDetails,
        name: String,
    ) -> Result<RemoteIdentifierOutcome, IdentifierServiceError> {
        let (identifier, _) = self
            .identifier_creator
            .get_or_create_remote_identifier(
                organisation_id,
                &details,
                IdentifierName::Name(name.clone()),
                false,
                None,
                None,
            )
            .await
            .error_while("creating remote identifier")?;

        // The upfront name pre-check guarantees no existing identifier in this
        // org carries the requested name, so a name mismatch on the returned
        // identifier means we got back an existing one for this material.
        Ok(if identifier.name == name {
            RemoteIdentifierOutcome::Created(identifier.id)
        } else {
            RemoteIdentifierOutcome::AlreadyExists(identifier.id)
        })
    }

    /// Creates a new identifier with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - identifier data
    pub async fn create_identifier(
        &self,
        request: CreateIdentifierRequestDTO,
    ) -> Result<IdentifierId, IdentifierServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(IdentifierServiceError::OrganisationDeactivated(
                request.organisation_id,
            ));
        }

        let identifier = self
            .transaction_manager
            .tx_with_config(
                async {
                    let now = crate::clock::now_utc();
                    let trust_information = request.trust_information;
                    let params = CreateLocalIdentifierRequestParams {
                        name: request.name,
                        organisation_id: request.organisation_id,
                        now,
                        autogenerated: false,
                        logo: request.logo,
                        translations: request.translations.map(Into::into),
                    };
                    let identifier = match (
                        request.did,
                        request.key_id,
                        request.key,
                        request.certificates,
                        request.certificate_authorities,
                    ) {
                        // IdentifierType::Did
                        (Some(did), None, None, None, None) => {
                            validate_identifier_type(
                                core_config::IdentifierType::Did,
                                &self.config.identifier,
                            )?;

                            let did_request =
                                to_create_did_request(&params.name, did, params.organisation_id);

                            self.identifier_creator
                                .create_local_identifier(
                                    params,
                                    CreateLocalIdentifierRequestType::Did(did_request),
                                )
                                .await
                                .error_while("creating local did identifier")?
                        }
                        // IdentifierType::Key
                        // Deprecated. Use the `key` field instead.
                        (None, Some(key_id), None, None, None) => {
                            warn!(
                                "Creating identifier with key_id is deprecated. Use key instead."
                            );
                            validate_identifier_type(
                                core_config::IdentifierType::Key,
                                &self.config.identifier,
                            )?;
                            let key = self
                                .key_repository
                                .get_key(&key_id)
                                .await
                                .error_while("getting key")?;

                            self.identifier_creator
                                .create_local_identifier(
                                    params,
                                    CreateLocalIdentifierRequestType::Key(key),
                                )
                                .await
                                .error_while("creating local key identifier")?
                        }
                        (
                            None,
                            None,
                            Some(CreateIdentifierKeyRequestDTO { key_id }),
                            None,
                            None,
                        ) => {
                            validate_identifier_type(
                                core_config::IdentifierType::Key,
                                &self.config.identifier,
                            )?;
                            let key = self
                                .key_repository
                                .get_key(&key_id)
                                .await
                                .error_while("getting key")?;

                            self.identifier_creator
                                .create_local_identifier(
                                    params,
                                    CreateLocalIdentifierRequestType::Key(key),
                                )
                                .await
                                .error_while("creating local key identifier")?
                        }
                        // IdentifierType::Certificate
                        (None, None, None, Some(certificate_requests), None) => {
                            validate_identifier_type(
                                core_config::IdentifierType::Certificate,
                                &self.config.identifier,
                            )?;

                            self.identifier_creator
                                .create_local_identifier(
                                    params,
                                    CreateLocalIdentifierRequestType::Certificate(
                                        certificate_requests,
                                    ),
                                )
                                .await
                                .error_while("creating local certificate identifier")?
                        }
                        // IdentifierType::Certificate authority
                        (None, None, None, None, Some(ca_requests)) => {
                            validate_identifier_type(
                                core_config::IdentifierType::CertificateAuthority,
                                &self.config.identifier,
                            )?;

                            self.identifier_creator
                                .create_local_identifier(
                                    params,
                                    CreateLocalIdentifierRequestType::CertificateAuthority(
                                        ca_requests,
                                    ),
                                )
                                .await
                                .error_while("creating local CA identifier")?
                        }
                        // invalid input combinations
                        _ => return Err(IdentifierServiceError::InvalidCreationInput),
                    };
                    self.create_trust_information(trust_information, &identifier, now)
                        .await?;
                    Ok(identifier)
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating identifier")??;
        tracing::info!(
            "Created identifier `{}` ({}) with type `{}`",
            identifier.name,
            identifier.id,
            identifier.data.r#type()
        );
        Ok(identifier.id)
    }

    async fn create_trust_information(
        &self,
        trust_information: Vec<CreateIdentifierTrustInformationRequestDTO>,
        identifier: &Identifier,
        now: OffsetDateTime,
    ) -> Result<(), IdentifierServiceError> {
        if trust_information.is_empty() {
            return Ok(());
        }

        let inputs: Vec<TrustInformationInput> = trust_information
            .iter()
            .map(|info| TrustInformationInput {
                data: info.data.clone(),
                r#type: info.r#type.clone().into(),
            })
            .collect();

        let enabled_ecosystems = self.ecosystem_provider.enabled_ecosystems();
        if enabled_ecosystems.is_empty() {
            return Err(IdentifierServiceError::NoEcosystemEnabledForTrustInformation);
        }

        let mut outcomes = EcosystemOutcomes::default();
        let mut parsed = None;
        for ecosystem in enabled_ecosystems {
            let ecosystem_id = ecosystem.config_name().to_owned();
            match ecosystem
                .parse_identifier_trust_information(identifier, &inputs)
                .await
            {
                Ok(result) => {
                    outcomes.record(ecosystem_id, Ok(()));
                    parsed = Some(result);
                    break;
                }
                Err(err) => outcomes.record(ecosystem_id, Err((&err).into())),
            }
        }
        let parsed = parsed.ok_or(IdentifierServiceError::TrustInformationRejected(outcomes))?;

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        for (trust_info, parsed_info) in trust_information.into_iter().zip(parsed) {
            let blob_id = Uuid::new_v4().into();
            blob_storage
                .create(Blob {
                    id: blob_id,
                    created_date: now,
                    last_modified: now,
                    value: trust_info.data.into_bytes(),
                    r#type: parsed_info.blob_type,
                })
                .await
                .error_while("saving trust information blob")?;

            self.identifier_trust_information_repository
                .create(IdentifierTrustInformation {
                    id: Uuid::new_v4().into(),
                    created_date: now,
                    last_modified: now,
                    valid_from: parsed_info.valid_from,
                    valid_to: parsed_info.valid_to,
                    intended_use: parsed_info.intended_use,
                    allowed_issuance_types: parsed_info.allowed_issuance_types,
                    allowed_verification_types: parsed_info.allowed_verification_types,
                    identifier_id: identifier.id,
                    blob_id,
                })
                .await
                .error_while("creating trust information")?;
        }
        Ok(())
    }

    pub async fn update_identifier(
        &self,
        id: &IdentifierId,
        request: PatchIdentifierRequestDTO,
    ) -> Result<(), IdentifierServiceError> {
        let identifier =
            self.identifier_repository
                .get(*id)
                .await
                .map_err(|error| match error {
                    DataLayerError::EntityNotFound { .. } => IdentifierServiceError::NotFound(*id),
                    error => error.error_while("getting identifier").into(),
                })?;

        if identifier.deleted_at.is_some() {
            return Err(IdentifierServiceError::NotFound(*id));
        }

        throw_if_org_id_not_matching_session(
            &identifier.organisation.id(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        if identifier.is_remote {
            return Err(IdentifierServiceError::InvalidUpdateForIdentifierType {
                identifier_type: identifier.data.r#type(),
                attribute: "remote",
            });
        }

        self.transaction_manager
            .tx_with_config(
                async {
                    let now = crate::clock::now_utc();
                    let mut key_id: Option<KeyId> = None;
                    let mut logo: Option<Option<BlobId>> = None;
                    let mut logo_blob_to_delete: Option<BlobId> = None;

                    if let Some(key_request) = request.key {
                        if !matches!(&identifier.data, IdentifierData::Key(_)) {
                            return Err(IdentifierServiceError::InvalidUpdateForIdentifierType {
                                identifier_type: identifier.data.r#type(),
                                attribute: "key",
                            });
                        }
                        let key = self
                            .key_repository
                            .get_key(&key_request.key_id)
                            .await
                            .error_while("getting key")?;
                        if key.is_remote() {
                            return Err(IdentifierServiceError::KeyMustNotBeRemote(key.name));
                        }
                        if key.organisation.id() != identifier.organisation.id() {
                            return Err(IdentifierServiceError::KeyOrganisationMismatch);
                        }
                        key_id = Some(key.id);
                    }

                    if let Some(did_request) = request.did {
                        let IdentifierData::Did(did) = &identifier.data else {
                            return Err(IdentifierServiceError::InvalidUpdateForIdentifierType {
                                identifier_type: identifier.data.r#type(),
                                attribute: "did",
                            });
                        };
                        if identifier.state != IdentifierState::Active {
                            return Err(IdentifierServiceError::DidKeysNotUpdatable(
                                *id,
                                format!("identifier is in state `{:?}`", identifier.state),
                            ));
                        }

                        self.identifier_creator
                            .update_local_did_keys(did.id(), did_request.keys)
                            .await
                            .error_while("updating DID keys")?;
                    }

                    match (request.logo, identifier.logo) {
                        (None, _) | (Some(None), None) => {}
                        (Some(None), Some(existing_logo_id)) => {
                            logo = Some(None);
                            logo_blob_to_delete = Some(existing_logo_id);
                        }
                        (Some(Some(new_logo)), Some(existing_logo_id)) => {
                            self.blob_storage_provider
                                .get_blob_storage(BlobStorageType::Db)?
                                .update(
                                    &existing_logo_id,
                                    UpdateBlobRequest {
                                        value: Some(new_logo.0.into_bytes()),
                                    },
                                )
                                .await
                                .error_while("updating identifier logo blob")?;
                        }
                        (Some(Some(new_logo)), None) => {
                            let blob_id = self
                                .identifier_creator
                                .persist_identifier_logo(new_logo.0, now)
                                .await
                                .error_while("persisting identifier logo")?;
                            logo = Some(Some(blob_id));
                        }
                    }

                    if let Some(translations) = request.translations {
                        let rows = build_identifier_translations(
                            identifier.id,
                            &identifier.name,
                            translations.map(Into::into),
                            now,
                            &self.config.global_settings.default_language,
                        );
                        self.localized_text_repository
                            .replace(&identifier.id.into(), rows)
                            .await
                            .error_while("replacing identifier translations")?;
                    }

                    if let Some(trust_information) = request.trust_information {
                        let old_trust_information = self
                            .identifier_trust_information_repository
                            .get_by_identifier_id(&identifier.id)
                            .await
                            .error_while("getting existing trust information")?;

                        self.identifier_trust_information_repository
                            .delete_by_identifier_id(&identifier.id)
                            .await
                            .error_while("deleting existing trust information")?;

                        if !old_trust_information.is_empty() {
                            let blob_storage = self
                                .blob_storage_provider
                                .get_blob_storage(BlobStorageType::Db)?;
                            for old in &old_trust_information {
                                blob_storage
                                    .delete(&old.blob_id)
                                    .await
                                    .error_while("deleting old trust information blob")?;
                            }
                        }

                        self.create_trust_information(trust_information, &identifier, now)
                            .await?;
                    }

                    self.identifier_repository
                        .update(
                            id,
                            UpdateIdentifierRequest {
                                key_id,
                                logo,
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating identifier")?;

                    if let Some(logo_id) = logo_blob_to_delete {
                        self.blob_storage_provider
                            .get_blob_storage(BlobStorageType::Db)?
                            .delete(&logo_id)
                            .await
                            .error_while("deleting identifier logo blob")?;
                    }

                    self.trust_list_regenerator
                        .regenerate_for_identifier(*id)
                        .await
                        .error_while("regenerating trust lists")?;

                    Ok::<_, IdentifierServiceError>(())
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("updating identifier")??;

        Ok(())
    }

    async fn prune_orphaned_trust_information(
        &self,
        identifier: &Identifier,
    ) -> Result<(), IdentifierServiceError> {
        let mut orphaned_ids: HashSet<IdentifierTrustInformationId> = HashSet::new();
        for ecosystem in self.ecosystem_provider.enabled_ecosystems() {
            let ids = ecosystem
                .orphaned_identifier_trust_information(identifier)
                .await
                .error_while("finding orphaned trust information")?;
            orphaned_ids.extend(ids);
        }
        if orphaned_ids.is_empty() {
            return Ok(());
        }

        let trust_information = identifier.trust_information.as_ref().await?.to_owned();
        let blob_ids: Vec<_> = trust_information
            .iter()
            .filter(|info| orphaned_ids.contains(&info.id))
            .map(|info| info.blob_id)
            .collect();

        for id in &orphaned_ids {
            self.identifier_trust_information_repository
                .delete(id)
                .await
                .error_while("deleting orphaned trust information")?;
        }

        if !blob_ids.is_empty() {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;
            blob_storage
                .delete_many(&blob_ids)
                .await
                .error_while("deleting orphaned trust information blobs")?;
        }

        Ok(())
    }

    /// Deletes an identifier
    ///
    /// # Arguments
    ///
    /// * `id` - Identifier uuid
    pub async fn delete_identifier(&self, id: &IdentifierId) -> Result<(), IdentifierServiceError> {
        let identifier = self
            .identifier_repository
            .get(*id)
            .await
            .error_while("getting identifier")?;
        throw_if_org_id_not_matching_session(
            &identifier.organisation.id(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        let certificates = match &identifier.data {
            IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) => {
                certificates.as_ref().await?.to_owned()
            }
            _ => vec![],
        };
        let name = identifier.name.clone();

        self.transaction_manager
            .tx(async {
                for cert in &certificates {
                    if cert.deleted_at.is_some() {
                        continue;
                    }
                    self.certificate_repository
                        .delete(cert)
                        .await
                        .error_while("cascading certificate delete")?;

                    tracing::info!("Deleted certificate `{}` ({})`", cert.name, cert.id);
                }
                if let IdentifierData::Did(did) = &identifier.data {
                    let did = did.as_ref().await?;
                    self.did_repository
                        .delete_did(&did)
                        .await
                        .error_while("deleting DID")?;
                    tracing::info!("Deleted DID `{}` ({})", did.name, did.id);
                }

                self.identifier_repository
                    .delete(id)
                    .await
                    .map_err(|e| match e {
                        DataLayerError::RecordNotUpdated(_) => {
                            IdentifierServiceError::NotFound(*id)
                        }
                        e => e.error_while("deleting identifier").into(),
                    })?;

                if let Some(logo_id) = identifier.logo {
                    self.blob_storage_provider
                        .get_blob_storage(BlobStorageType::Db)?
                        .delete(&logo_id)
                        .await
                        .error_while("deleting identifier logo blob")?;
                }

                Ok::<_, IdentifierServiceError>(())
            })
            .await
            .error_while("transactional identifier delete")??;

        tracing::info!("Deleted identifier `{}` ({id})`", name);
        Ok(())
    }

    pub async fn resolve_trust_entries(
        &self,
        request: ResolveTrustEntriesRequestDTO,
    ) -> Result<Vec<ResolvedTrustEntriesResponseDTO>, IdentifierServiceError> {
        let identifiers = self
            .identifier_repository
            .get_identifier_list(IdentifierListQuery {
                include_count: false,
                filtering: Some(IdentifierFilterValue::Ids(request.identifiers).condition()),
                ..Default::default()
            })
            .await
            .error_while("getting identifiers")?
            .values;

        if identifiers.is_empty() {
            return Ok(vec![]);
        }
        let Ok(organisation_id) = identifiers
            .iter()
            .map(|identifier| identifier.organisation.id())
            .unique()
            .exactly_one()
        else {
            return Err(ValidationError::Forbidden
                .error_while("checking organisations")
                .into());
        };
        throw_if_org_id_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;

        let mut collection_ids: Vec<_> = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                include_count: false,
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId {
                        id: organisation_id,
                        include_inherited_collections: true,
                    }
                    .condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust collections")?
            .values
            .into_iter()
            .map(|collection| collection.id)
            .collect();
        if let Some(requested_ids) = &request.trust_collection_ids {
            collection_ids.retain(|id| requested_ids.contains(id));
        }

        let requested_roles = request.roles.clone().unwrap_or_default();
        let trust_list_subscriptions = self
            .fetch_trust_list_subscriptions(request.roles, Some(collection_ids))
            .await?;
        let all_resolved_entries = self
            .resolve_trust_list_subscriptions(
                &identifiers,
                trust_list_subscriptions,
                &requested_roles,
            )
            .await?;

        let identifier_id_to_entries = group_entries_by_identifier_id(all_resolved_entries).await?;
        Ok(assign_identifiers_to_entries(
            identifiers,
            identifier_id_to_entries,
        ))
    }

    async fn resolve_trust_list_subscriptions(
        &self,
        valid_identifiers: &[Identifier],
        trust_list_subscriptions: Vec<TrustListSubscription>,
        requested_roles: &[TrustListRoleEnum],
    ) -> Result<
        Vec<Vec<(IdentifierId, TrustEntityResponse, TrustListSubscription)>>,
        IdentifierServiceError,
    > {
        let mut all_resolved_entries = Vec::new();
        for mut trust_list_subscription in trust_list_subscriptions {
            let resolved_entries = self
                .resolve_trust_list_subscription(
                    valid_identifiers,
                    &mut trust_list_subscription,
                    requested_roles,
                )
                .await?;
            all_resolved_entries.push(resolved_entries);
        }
        Ok(all_resolved_entries)
    }

    async fn resolve_trust_list_subscription(
        &self,
        identifiers: &[Identifier],
        trust_list_subscription: &mut TrustListSubscription,
        requested_roles: &[TrustListRoleEnum],
    ) -> Result<
        Vec<(IdentifierId, TrustEntityResponse, TrustListSubscription)>,
        IdentifierServiceError,
    > {
        let trust_list_subscriber = self
            .fetch_trust_list_subscriber(trust_list_subscription)
            .await?;
        let valid_identifiers =
            filter_resolvable_identifiers(identifiers, &trust_list_subscriber.get_capabilities());

        let resolved_entries_result = trust_list_subscriber
            .resolve_entries(
                &trust_list_subscription
                    .reference
                    .parse::<Url>()
                    .map_err(|e| {
                        IdentifierServiceError::MappingError(format!(
                            "failed to parse reference: {e}"
                        ))
                    })?,
                valid_identifiers.as_ref(),
            )
            .await;

        let resolved_entries = match resolved_entries_result {
            Err(e) => {
                warn!(
                    error_code = %e.error_code(),
                    cause = ?e,
                    reference = %trust_list_subscription.reference,
                    "Failed to resolve entries for trust list subscription {}",
                    trust_list_subscription.reference
                );
                return Ok(Vec::new());
            }
            Ok(resolved_entries) => resolved_entries,
        };

        Ok(resolved_entries
            .into_iter()
            .flat_map(|(identifier_id, entities)| {
                entities
                    .into_iter()
                    .map(move |entity| (identifier_id, entity))
            })
            .filter(|(_, trust_entity)| {
                entry_matches_requested_roles(
                    trust_entity,
                    trust_list_subscription,
                    requested_roles,
                )
            })
            .map(|(identifier_id, trust_entity)| {
                (identifier_id, trust_entity, trust_list_subscription.clone())
            })
            .collect())
    }

    async fn fetch_trust_collections(
        &self,
        trust_list_collection_ids: Vec<TrustCollectionId>,
    ) -> Result<HashMap<TrustCollectionId, TrustCollection>, IdentifierServiceError> {
        Ok(self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                include_count: false,
                filtering: Some(
                    TrustCollectionFilterValue::Ids(trust_list_collection_ids).condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust list collections")?
            .values
            .into_iter()
            .map(|tc| (tc.id, tc))
            .collect())
    }

    async fn fetch_trust_list_subscriptions(
        &self,
        trust_list_roles: Option<Vec<TrustListRoleEnum>>,
        trust_collection_ids: Option<Vec<TrustCollectionId>>,
    ) -> Result<Vec<TrustListSubscription>, IdentifierServiceError> {
        let mut trust_list_subscriptions = self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                include_count: false,
                filtering: Some(calculate_trust_list_subscription_filtering(
                    trust_list_roles,
                    trust_collection_ids,
                )),
                ..Default::default()
            })
            .await
            .error_while("getting trust list subscriptions")?
            .values;

        let trust_collection_ids = trust_list_subscriptions
            .iter()
            .map(|tls| tls.trust_collection.id())
            .unique()
            .collect();

        let trust_list_collections = self
            .fetch_trust_collections(trust_collection_ids)
            .await
            .error_while("getting trust list subscriptions")?;

        for trust_list_subscription in &mut trust_list_subscriptions {
            if let Some(trust_collection) =
                trust_list_collections.get(trust_list_subscription.trust_collection.id_ref())
            {
                trust_list_subscription.trust_collection = trust_collection.to_owned().into();
            }
        }
        Ok(trust_list_subscriptions)
    }

    async fn fetch_trust_list_subscriber(
        &self,
        trust_list_subscription: &TrustListSubscription,
    ) -> Result<Arc<dyn TrustListSubscriber>, IdentifierServiceError> {
        self.trust_list_subscriber_provider
            .get(&trust_list_subscription.r#type)
            .map_err(|_| {
                IdentifierServiceError::MissingTrustListSubscriber(
                    trust_list_subscription.r#type.clone(),
                )
            })
    }

    /// Adds one or more certificates to an existing local CERTIFICATE identifier.
    pub async fn add_certificates(
        &self,
        id: &IdentifierId,
        requests: Vec<CreateCertificateRequestDTO>,
    ) -> Result<Vec<CertificateId>, IdentifierServiceError> {
        let identifier = self.get_identifier_for_certificate_mutation(id).await?;

        if !matches!(identifier.data, IdentifierData::Certificate(_)) {
            return Err(IdentifierServiceError::InvalidIdentifierTypeForCertificateOperation);
        }

        let ids = self
            .transaction_manager
            .tx(async {
                let certificates = self
                    .identifier_creator
                    .prepare_certificates(&identifier, requests)
                    .await
                    .error_while("preparing certificates")?;
                self.persist_new_certificates(&identifier, certificates)
                    .await
            }
            .boxed())
            .await
            .error_while("adding certificates")??;

        Ok(ids)
    }

    /// Adds one or more certificates to an existing local CA identifier.
    pub async fn add_certificate_authorities(
        &self,
        id: &IdentifierId,
        requests: Vec<CreateCertificateAuthorityRequestDTO>,
    ) -> Result<Vec<CertificateId>, IdentifierServiceError> {
        let identifier = self.get_identifier_for_certificate_mutation(id).await?;

        if !matches!(identifier.data, IdentifierData::CertificateAuthority(_)) {
            return Err(IdentifierServiceError::InvalidIdentifierTypeForCertificateOperation);
        }

        let ids = self
            .transaction_manager
            .tx(async {
                let certificates = self
                    .identifier_creator
                    .prepare_certificate_authorities(&identifier, requests)
                    .await
                    .error_while("preparing certificate authorities")?;
                self.persist_new_certificates(&identifier, certificates)
                    .await
            }
            .boxed())
            .await
            .error_while("adding certificate authorities")??;

        Ok(ids)
    }

    /// Removes (soft-deletes) a certificate from an existing local CERTIFICATE identifier. Fails
    /// if it would be the identifier's last remaining non-deleted certificate.
    pub async fn remove_certificate(
        &self,
        identifier_id: &IdentifierId,
        certificate_id: &CertificateId,
    ) -> Result<(), IdentifierServiceError> {
        let identifier = self
            .get_identifier_for_certificate_mutation(identifier_id)
            .await?;

        if !matches!(identifier.data, IdentifierData::Certificate(_)) {
            return Err(IdentifierServiceError::InvalidIdentifierTypeForCertificateOperation);
        }

        self.remove_certificate_internal(identifier, certificate_id)
            .await
    }

    /// Removes (soft-deletes) a certificate from an existing local CA identifier. Fails if it
    /// would be the identifier's last remaining non-deleted certificate.
    pub async fn remove_certificate_authority(
        &self,
        identifier_id: &IdentifierId,
        certificate_id: &CertificateId,
    ) -> Result<(), IdentifierServiceError> {
        let identifier = self
            .get_identifier_for_certificate_mutation(identifier_id)
            .await?;

        if !matches!(identifier.data, IdentifierData::CertificateAuthority(_)) {
            return Err(IdentifierServiceError::InvalidIdentifierTypeForCertificateOperation);
        }

        self.remove_certificate_internal(identifier, certificate_id)
            .await
    }

    async fn remove_certificate_internal(
        &self,
        identifier: Identifier,
        certificate_id: &CertificateId,
    ) -> Result<(), IdentifierServiceError> {
        let certificates = match &identifier.data {
            IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) => {
                certificates.as_ref().await?.to_owned()
            }
            _ => vec![],
        };

        let certificate = certificates
            .iter()
            .find(|certificate| {
                &certificate.id == certificate_id && certificate.deleted_at.is_none()
            })
            .cloned()
            .ok_or_else(|| -> IdentifierServiceError {
                DataLayerError::EntityNotFound {
                    kind: EntityKind::Certificate,
                    id: (*certificate_id).into(),
                }
                .error_while("getting certificate")
                .into()
            })?;

        let active_count = certificates
            .iter()
            .filter(|certificate| certificate.deleted_at.is_none())
            .count();
        if active_count <= 1 {
            return Err(IdentifierServiceError::CannotRemoveLastCertificate);
        }

        let identifier_id = identifier.id;
        self.transaction_manager
            .tx(async {
                self.certificate_repository
                    .delete(&certificate)
                    .await
                    .error_while("deleting certificate")?;

                self.identifier_repository
                    .update(&identifier_id, UpdateIdentifierRequest::default())
                    .await
                    .error_while("updating identifier")?;

                let identifier = self
                    .identifier_repository
                    .get(identifier_id)
                    .await
                    .error_while("getting identifier")?;

                self.prune_orphaned_trust_information(&identifier).await?;

                self.trust_list_regenerator
                    .regenerate_for_identifier(identifier_id)
                    .await
                    .error_while("regenerating trust lists")?;

                Ok::<_, IdentifierServiceError>(())
            }
            .boxed())
            .await
            .error_while("removing certificate")??;

        Ok(())
    }

    async fn get_identifier_for_certificate_mutation(
        &self,
        id: &IdentifierId,
    ) -> Result<Identifier, IdentifierServiceError> {
        let identifier =
            self.identifier_repository
                .get(*id)
                .await
                .map_err(|error| match error {
                    DataLayerError::EntityNotFound { .. } => IdentifierServiceError::NotFound(*id),
                    error => error.error_while("getting identifier").into(),
                })?;

        if identifier.deleted_at.is_some() {
            return Err(IdentifierServiceError::NotFound(*id));
        }

        throw_if_org_id_not_matching_session(
            &identifier.organisation.id(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        if identifier.is_remote {
            return Err(IdentifierServiceError::InvalidIdentifierTypeForCertificateOperation);
        }

        Ok(identifier)
    }

    async fn persist_new_certificates(
        &self,
        identifier: &Identifier,
        certificates: Vec<Certificate>,
    ) -> Result<Vec<CertificateId>, IdentifierServiceError> {
        let mut ids = Vec::with_capacity(certificates.len());
        let mut has_active = false;

        for certificate in certificates {
            if certificate.state == CertificateState::Active {
                has_active = true;
            }
            let certificate_id = certificate.id;
            self.certificate_repository
                .create(certificate)
                .await
                .map_err(|error| -> IdentifierServiceError {
                    match error {
                        DataLayerError::AlreadyExists(_) => {
                            identifier_creator::Error::CertificateAlreadyExists
                                .error_while("creating certificate")
                                .into()
                        }
                        error => error.error_while("creating certificate").into(),
                    }
                })?;
            ids.push(certificate_id);
        }

        let reactivate = identifier.state == IdentifierState::Deactivated && has_active;
        self.identifier_repository
            .update(
                &identifier.id,
                UpdateIdentifierRequest {
                    state: reactivate.then_some(IdentifierState::Active),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating identifier")?;

        self.trust_list_regenerator
            .regenerate_for_identifier(identifier.id)
            .await
            .error_while("regenerating trust lists")?;

        Ok(ids)
    }
}

fn filter_resolvable_identifiers(
    identifiers: &[Identifier],
    capabilities: &TrustListSubscriberCapabilities,
) -> Vec<Identifier> {
    identifiers
        .iter()
        .filter(|identifier| {
            if identifier.is_remote {
                capabilities
                    .features
                    .contains(&Feature::SupportsRemoteIdentifiers)
            } else {
                capabilities
                    .features
                    .contains(&Feature::SupportsLocalIdentifiers)
            }
        })
        .filter(|identifier| {
            capabilities
                .resolvable_identifier_types
                .contains(&identifier.data.r#type())
        })
        .cloned()
        .collect()
}

fn entry_matches_requested_roles(
    entity: &TrustEntityResponse,
    subscription: &TrustListSubscription,
    requested_roles: &[TrustListRoleEnum],
) -> bool {
    if requested_roles.is_empty() || subscription.role.is_some() {
        return true;
    }
    entity
        .derived_role
        .is_some_and(|role| requested_roles.contains(&role))
}

async fn group_entries_by_identifier_id(
    all_resolved_entries: Vec<Vec<(IdentifierId, TrustEntityResponse, TrustListSubscription)>>,
) -> Result<HashMap<IdentifierId, Vec<ResolvedTrustEntryResponseDTO>>, IdentifierServiceError> {
    let mut identifier_to_entries = HashMap::new();
    for resolved_entries in all_resolved_entries {
        for (identifier_id, trust_entity, trust_list_subscription) in resolved_entries {
            identifier_to_entries
                .entry(identifier_id)
                .or_insert(Vec::new())
                .push(ResolvedTrustEntryResponseDTO {
                    metadata: Some(trust_entity.metadata),
                    source: ResolvedTrustEntrySourceResponseDTO::try_from(trust_list_subscription)
                        .await?,
                });
        }
    }
    Ok(identifier_to_entries)
}

fn assign_identifiers_to_entries(
    identifiers: Vec<Identifier>,
    mut identifier_id_to_entries: HashMap<IdentifierId, Vec<ResolvedTrustEntryResponseDTO>>,
) -> Vec<ResolvedTrustEntriesResponseDTO> {
    identifiers
        .into_iter()
        .map(|identifier| {
            let trust_entries = identifier_id_to_entries
                .remove(&identifier.id)
                .unwrap_or_default();
            ResolvedTrustEntriesResponseDTO {
                identifier: identifier.into(),
                trust_entries,
            }
        })
        .collect()
}

fn calculate_trust_list_subscription_filtering(
    roles: Option<Vec<TrustListRoleEnum>>,
    trust_collection_ids: Option<Vec<TrustCollectionId>>,
) -> ListFilterCondition<TrustListSubscriptionFilterValue> {
    let filter_roles = roles.map(TrustListSubscriptionFilterValue::Role);
    let filter_trust_collections =
        trust_collection_ids.map(TrustListSubscriptionFilterValue::TrustCollectionId);

    ListFilterCondition::<TrustListSubscriptionFilterValue>::default()
        & filter_roles
        & filter_trust_collections
}
