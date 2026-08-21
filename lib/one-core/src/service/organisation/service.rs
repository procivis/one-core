use std::collections::HashMap;

use shared_types::{EcosystemId, IdentifierId, OrganisationId, TrustCollectionId};

use super::OrganisationService;
use super::dto::{
    CreateOrganisationRequestDTO, EcosystemInfoDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListResponseDTO, InstanceDetailResponseDTO, OrganisationFilterParamsDTO,
    TrustCollectionInfoDTO, UpsertOrganisationRequestDTO,
};
use super::error::OrganisationServiceError;
use super::mapper::{
    detail_from_model, group_remote_trust_collections_by_local_id, list_item_from_model,
    merge_ecosystems, prepare_trust_collection_info, request_to_model,
    set_active_trust_collections,
};
use super::validator::{
    validate_ecosystem_enforcement, validate_parent_organisation, validate_verifier_provider,
    validate_wallet_provider, validate_wallet_provider_issuer,
};
use crate::config::core_config::ConfigExt;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::identifier::{Identifier, IdentifierFilterValue, IdentifierListQuery};
use crate::model::instance::{InstanceFilterValue, InstanceRole};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::{
    Organisation, OrganisationConfiguration, SortableOrganisationColumn, UpdateOrganisationRequest,
};
use crate::model::trust_collection::TrustCollectionFilterValue;
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::service::instance::service::provider_metadata_url;
use crate::service::managed_instance::dto::{EcosystemMetadataDTO, ProviderTrustCollectionDTO};
use crate::service::managed_instance::ecosystem_metadata::{
    ecosystem_display, provider_trust_collections,
};

impl OrganisationService {
    /// Returns all existing organisations
    pub async fn get_organisation_list(
        &self,
        filter_params: ListQueryDTO<SortableOrganisationColumn, OrganisationFilterParamsDTO>,
    ) -> Result<GetOrganisationListResponseDTO, OrganisationServiceError> {
        let organisations = self
            .organisation_repository
            .get_organisation_list(filter_params.into())
            .await
            .error_while("getting organisations")?;

        let provider_issuers: Vec<IdentifierId> = organisations
            .values
            .iter()
            .flat_map(|organisation| {
                [
                    organisation.wallet_provider_issuer,
                    organisation.verifier_provider_issuer,
                ]
            })
            .flatten()
            .collect();

        let identifiers: HashMap<IdentifierId, Identifier> = if provider_issuers.is_empty() {
            Default::default()
        } else {
            self.identifier_repository
                .get_identifier_list(IdentifierListQuery {
                    filtering: Some(IdentifierFilterValue::Ids(provider_issuers).condition()),
                    ..Default::default()
                })
                .await
                .error_while("getting identifiers")?
                .values
                .into_iter()
                .map(|identifier| (identifier.id, identifier))
                .collect()
        };

        let details = organisations
            .values
            .into_iter()
            .map(|organisation| {
                let wallet_provider_issuer = organisation
                    .wallet_provider_issuer
                    .as_ref()
                    .and_then(|issuer| identifiers.get(issuer))
                    .map(ToOwned::to_owned);
                let verifier_provider_issuer = organisation
                    .verifier_provider_issuer
                    .as_ref()
                    .and_then(|issuer| identifiers.get(issuer))
                    .map(ToOwned::to_owned);

                list_item_from_model(
                    organisation,
                    wallet_provider_issuer,
                    verifier_provider_issuer,
                )
            })
            .collect();

        Ok(GetOrganisationListResponseDTO {
            values: details,
            total_items: organisations.total_items,
            total_pages: organisations.total_pages,
        })
    }

    /// Returns details of an organisation
    ///
    /// # Arguments
    ///
    /// * `OrganisationId` - Id of an existing organisation
    pub async fn get_organisation(
        &self,
        id: &OrganisationId,
    ) -> Result<GetOrganisationDetailsResponseDTO, OrganisationServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(id)
            .await
            .error_while("getting organisation")?;

        let wallet_provider_issuer =
            if let Some(identifier_id) = &organisation.wallet_provider_issuer {
                Some(
                    self.identifier_repository
                        .get(*identifier_id)
                        .await
                        .error_while("getting identifier")?,
                )
            } else {
                None
            };
        let verifier_provider_issuer =
            if let Some(identifier_id) = &organisation.verifier_provider_issuer {
                Some(
                    self.identifier_repository
                        .get(*identifier_id)
                        .await
                        .error_while("getting identifier")?,
                )
            } else {
                None
            };

        let wallet_instance = self
            .load_instance_details(InstanceRole::Wallet, organisation.id)
            .await?;
        let verifier_instance = self
            .load_instance_details(InstanceRole::Verifier, organisation.id)
            .await?;

        let ecosystems = self.ecosystems_of_organisation(&organisation).await?;

        Ok(detail_from_model(
            organisation,
            ecosystems,
            wallet_provider_issuer,
            verifier_provider_issuer,
            wallet_instance,
            verifier_instance,
        ))
    }

    async fn get_organisation_if_exists(
        &self,
        id: &OrganisationId,
    ) -> Result<Option<Organisation>, DataLayerError> {
        match self.organisation_repository.get_organisation(id).await {
            Ok(organisation) => Ok(Some(organisation)),
            Err(DataLayerError::EntityNotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn load_instance_details(
        &self,
        role: InstanceRole,
        organisation_id: OrganisationId,
    ) -> Result<Option<InstanceDetailResponseDTO>, OrganisationServiceError> {
        let Some(instance) = self
            .instance_repository
            .get_by_role(role, organisation_id)
            .await
            .error_while("getting instance with authentication key")?
        else {
            return Ok(None);
        };
        let Some(authentication_key) = instance.authentication_key else {
            return Ok(None);
        };

        Ok(Some(InstanceDetailResponseDTO {
            id: instance.id,
            provider_url: instance.provider_url,
            provider_name: instance.provider_name,
            authentication_key_type: authentication_key.as_ref().await?.key_type.to_owned(),
        }))
    }

    /// Accepts optional Uuid and optional name of new organisation
    /// and returns newly created organisation uuid.
    ///
    /// # Arguments
    ///
    /// * `CreateOrganisationRequestDTO` - Optional Id and name for a new organisation. If not set then the
    ///   ID will be created automatically and the name will be equal to the textual representation of the id.
    pub async fn create_organisation(
        &self,
        request: CreateOrganisationRequestDTO,
    ) -> Result<OrganisationId, OrganisationServiceError> {
        let organisation = request_to_model(request, &self.organisation_repository);
        if let Some(parent_organisation) = &organisation.parent_organisation {
            validate_parent_organisation(
                organisation.id,
                parent_organisation.id(),
                &*self.organisation_repository,
            )
            .await?;
        }

        let result = self
            .organisation_repository
            .create_organisation(organisation)
            .await;

        match result {
            Ok(uuid) => {
                tracing::info!("Created organisation {}", uuid);
                Ok(uuid)
            }
            Err(DataLayerError::AlreadyExists) => Err(OrganisationServiceError::AlreadyExists),
            Err(err) => Err(err.error_while("creating organisation").into()),
        }
    }

    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestDTO,
    ) -> Result<(), OrganisationServiceError> {
        let existing_organisation = self
            .get_organisation_if_exists(&request.id)
            .await
            .error_while("getting organisation")?;
        let existing_id = existing_organisation.as_ref().map(|org| &org.id);

        if let Some(Some(issuer)) = request.wallet_provider_issuer {
            validate_wallet_provider_issuer(existing_id, issuer, &*self.identifier_repository)
                .await?;
        }

        if let Some(Some(wallet_provider)) = &request.wallet_provider {
            validate_wallet_provider(
                request.id,
                wallet_provider,
                &self.core_config,
                &*self.organisation_repository,
            )
            .await?;
        }

        if let Some(Some(issuer)) = request.verifier_provider_issuer {
            validate_wallet_provider_issuer(existing_id, issuer, &*self.identifier_repository)
                .await?;
        }

        if let Some(Some(verifier_provider)) = &request.verifier_provider {
            validate_verifier_provider(
                request.id,
                verifier_provider,
                &self.core_config,
                &*self.organisation_repository,
            )
            .await?;
        }

        if let Some(Some(parent_id)) = request.parent_organisation {
            validate_parent_organisation(request.id, parent_id, &*self.organisation_repository)
                .await?;
        }

        let organisation_id = request.id;
        let trust_collections = request.trust_collections.clone();

        if let Some(trust_collections) = &trust_collections {
            // A not-yet-existing organisation can't have both a wallet and a verifier
            // instance linked yet, so there's nothing to validate in that case.
            if let Some(organisation) = &existing_organisation {
                self.validate_single_provider_trust_collections(organisation, trust_collections)
                    .await?;
            }
        }

        if let Some(update) = &request.configuration {
            validate_ecosystem_enforcement(
                existing_organisation.as_ref(),
                update,
                &*self.instance_repository,
                &*self.wallet_provider_client,
                &*self.verifier_provider_client,
            )
            .await?;
        }

        let existing_configuration = existing_organisation
            .as_ref()
            .map(|org| org.configuration.clone())
            .unwrap_or_default();
        let previously_selected_ecosystems = existing_configuration.selected_ecosystems.clone();
        let configuration =
            request
                .configuration
                .as_ref()
                .map(|update| OrganisationConfiguration {
                    selected_ecosystems: update
                        .selected_ecosystems
                        .clone()
                        .unwrap_or(existing_configuration.selected_ecosystems),
                    enforce_ecosystem_as_issuer: update
                        .enforce_ecosystem_as_issuer
                        .unwrap_or(existing_configuration.enforce_ecosystem_as_issuer),
                    enforce_ecosystem_as_holder: update
                        .enforce_ecosystem_as_holder
                        .unwrap_or(existing_configuration.enforce_ecosystem_as_holder),
                    enforce_ecosystem_as_verifier: update
                        .enforce_ecosystem_as_verifier
                        .unwrap_or(existing_configuration.enforce_ecosystem_as_verifier),
                });
        let ecosystem_selection_changed = configuration.as_ref().is_some_and(|configuration| {
            configuration.selected_ecosystems != previously_selected_ecosystems
        });

        let success_log = format!("Updated organisation {}", request.id);
        let mut update_request: UpdateOrganisationRequest = request.clone().into();
        update_request.configuration = configuration;
        let result = self
            .organisation_repository
            .update_organisation(&request.id, update_request)
            .await;

        let mut updated = true;
        match result {
            Ok(_) => tracing::info!(message = success_log),
            Err(DataLayerError::AlreadyExists) => {
                return Err(OrganisationServiceError::AlreadyExists);
            }
            Err(DataLayerError::RecordNotUpdated) => {
                // Organisation does not exist, create a new one instead.
                self.create_organisation(request.into()).await?;
                updated = false;
            }
            Err(err) => return Err(err.error_while("updating organisation").into()),
        }

        if let Some(trust_collections) = trust_collections {
            set_active_trust_collections(
                trust_collections,
                organisation_id,
                self.trust_collection_repository.as_ref(),
                self.trust_subscription_repository.as_ref(),
                self.trust_list_subscription_sync.as_ref(),
            )
            .await
            .error_while("setting active trust collections")?;
        }

        // An organisation just created has no instance to sync with yet, so only an update
        // can change a selection that has anything to pull in.
        if updated && ecosystem_selection_changed {
            self.sync_ecosystems(organisation_id).await?;
        }

        Ok(())
    }

    /// Pulls in what the organisation's providers advertise for its selected ecosystems:
    /// their trust collections, which are mirrored and subscribed to, and their credential
    /// and proof schemas, which are imported.
    ///
    /// The periodic `ECOSYSTEM_SYNC` task does the same, but an organisation that just
    /// enabled an ecosystem should not have to wait for its next run.
    async fn sync_ecosystems(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<(), OrganisationServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id)
            .await
            .error_while("getting organisation")?;

        self.ecosystem_sync
            .sync_organisation(&organisation)
            .await
            .error_while("syncing ecosystems")?;

        Ok(())
    }

    /// Returns the trust collections available to an organisation's wallet and/or verifier
    /// provider, annotated with whether the organisation selected the ecosystem owning each
    /// one.
    /// Replaces the instance-scoped `GET /api/holder-wallet-instance/v1/{id}/trust-collections`.
    pub async fn get_trust_collections(
        &self,
        id: &OrganisationId,
    ) -> Result<Vec<TrustCollectionInfoDTO>, OrganisationServiceError> {
        let Some(organisation) = self
            .get_organisation_if_exists(id)
            .await
            .error_while("getting organisation")?
        else {
            return Ok(vec![]);
        };

        let remote_trust_collections = self.fetch_remote_trust_collections(&organisation).await?;
        if remote_trust_collections.is_empty() {
            return Ok(vec![]);
        }

        Ok(prepare_trust_collection_info(
            self.trust_collection_repository.as_ref(),
            remote_trust_collections
                .into_iter()
                .map(|(_, collection)| collection)
                .collect(),
            &organisation,
        )
        .await
        .error_while("preparing trust collection info")?)
    }

    /// Returns the ecosystems offered to an organisation by its wallet and/or verifier
    /// provider, annotated with whether the organisation currently selected each one.
    ///
    /// An organisation without any managed instance is offered the ecosystems this core is
    /// configured for.
    pub async fn get_ecosystems(
        &self,
        id: &OrganisationId,
    ) -> Result<Vec<EcosystemInfoDTO>, OrganisationServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(id)
            .await
            .error_while("getting organisation")?;

        self.ecosystems_of_organisation(&organisation).await
    }

    /// Returns the ecosystems offered to an organisation, see [`Self::get_ecosystems`].
    async fn ecosystems_of_organisation(
        &self,
        organisation: &Organisation,
    ) -> Result<Vec<EcosystemInfoDTO>, OrganisationServiceError> {
        let selected_ecosystems = &organisation.configuration.selected_ecosystems;

        let Some(remote_ecosystems) = self.fetch_remote_ecosystems(organisation).await? else {
            // Without a linked instance there is no provider advertising ecosystems, so the
            // organisation is offered everything this core is configured for.
            return self.configured_ecosystems(selected_ecosystems);
        };

        let mut result = vec![];
        for ecosystem in remote_ecosystems {
            // An ecosystem the local core is not configured for cannot be used, which is a
            // misconfiguration on the side of the provider advertising it.
            if let Err(error) = self.core_config.ecosystem.get_if_enabled(&ecosystem.name) {
                tracing::warn!(
                    "Provider of organisation `{}` advertises ecosystem `{}` unknown to this core: {error}",
                    organisation.id,
                    ecosystem.name
                );
                continue;
            }

            result.push(EcosystemInfoDTO {
                selected: selected_ecosystems.contains(&ecosystem.name),
                default_selected: ecosystem.default_selected,
                name: ecosystem.name,
                display_name: ecosystem.display_name,
                description: ecosystem.description,
                logo: ecosystem.logo,
            });
        }

        Ok(result)
    }

    /// Lists the ecosystems this core is configured for, as offered to an organisation that
    /// has no managed instance to advertise them.
    fn configured_ecosystems(
        &self,
        selected_ecosystems: &[EcosystemId],
    ) -> Result<Vec<EcosystemInfoDTO>, OrganisationServiceError> {
        self.core_config
            .ecosystem
            .iter_enabled()
            .map(|(name, fields)| {
                let display = ecosystem_display(fields)?;

                Ok(EcosystemInfoDTO {
                    selected: selected_ecosystems.contains(name),
                    default_selected: false,
                    name: name.to_owned(),
                    display_name: display.display_name,
                    description: display.description,
                    logo: display.logo,
                })
            })
            .collect()
    }

    /// Fetches the ecosystems advertised by an organisation's linked wallet and/or verifier
    /// managed instance. Both providers may advertise the same ecosystem, in which case the
    /// two advertisements are merged into a single entry, see [`merge_ecosystems`].
    ///
    /// Returns `None` when the organisation has no linked instance, so no provider advertises
    /// anything to it.
    async fn fetch_remote_ecosystems(
        &self,
        organisation: &Organisation,
    ) -> Result<Option<Vec<EcosystemMetadataDTO>>, OrganisationServiceError> {
        let wallet_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Wallet, organisation.id)
            .await
            .error_while("getting wallet instance")?;
        let verifier_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Verifier, organisation.id)
            .await
            .error_while("getting verifier instance")?;

        if wallet_instance.is_none() && verifier_instance.is_none() {
            return Ok(None);
        }

        let mut result = vec![];

        if let Some(wallet_instance) = wallet_instance {
            let metadata = self
                .wallet_provider_client
                .get_wallet_provider_metadata(wallet_instance.into())
                .await
                .error_while("getting wallet provider metadata")?;
            result.extend(metadata.ecosystems);
        }

        if let Some(verifier_instance) = verifier_instance {
            let metadata_url = provider_metadata_url(
                &verifier_instance.provider_url,
                &verifier_instance.provider_name,
                InstanceRole::Verifier,
            );
            let metadata = self
                .verifier_provider_client
                .get_verifier_provider_metadata(&metadata_url)
                .await
                .error_while("getting verifier provider metadata")?;
            result.extend(metadata.ecosystems);
        }

        Ok(Some(merge_ecosystems(result)))
    }

    /// Fetches the trust collections advertised by an organisation's linked wallet and/or
    /// verifier managed instance, each tagged with the provider role that exposes it.
    async fn fetch_remote_trust_collections(
        &self,
        organisation: &Organisation,
    ) -> Result<Vec<(InstanceRole, ProviderTrustCollectionDTO)>, OrganisationServiceError> {
        let mut result = vec![];

        let wallet_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Wallet, organisation.id)
            .await
            .error_while("getting wallet instance")?;
        if let Some(wallet_instance) = wallet_instance {
            let metadata = self
                .wallet_provider_client
                .get_wallet_provider_metadata(wallet_instance.into())
                .await
                .error_while("getting wallet provider metadata")?;
            result.extend(
                provider_trust_collections(&metadata.ecosystems)
                    .into_iter()
                    .map(|collection| (InstanceRole::Wallet, collection)),
            );
        }

        let verifier_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Verifier, organisation.id)
            .await
            .error_while("getting wallet instance")?;
        if let Some(verifier_instance) = verifier_instance {
            let metadata_url = provider_metadata_url(
                &verifier_instance.provider_url,
                &verifier_instance.provider_name,
                InstanceRole::Verifier,
            );
            let metadata = self
                .verifier_provider_client
                .get_verifier_provider_metadata(&metadata_url)
                .await
                .error_while("getting verifier provider metadata")?;
            result.extend(
                provider_trust_collections(&metadata.ecosystems)
                    .into_iter()
                    .map(|collection| (InstanceRole::Verifier, collection)),
            );
        }

        Ok(result)
    }

    /// When an organisation has both a wallet and a verifier instance, each provider
    /// may expose its own set of trust collections. Subscribing to collections from both
    /// providers at once is not supported, so this rejects a request unless every requested
    /// collection can be satisfied by a single provider (collections not tied to either
    /// remote provider, e.g. locally managed ones, don't count against either side).
    async fn validate_single_provider_trust_collections(
        &self,
        organisation: &Organisation,
        trust_collections: &[TrustCollectionId],
    ) -> Result<(), OrganisationServiceError> {
        if trust_collections.is_empty() {
            return Ok(());
        }

        let num_instances = self
            .instance_repository
            .list(ListQuery {
                filtering: Some(
                    InstanceFilterValue::OrganisationIds(vec![organisation.id]).condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting instances")?
            .total_items;
        if num_instances <= 1 {
            return Ok(());
        }

        let remote_trust_collections = self.fetch_remote_trust_collections(organisation).await?;
        let local_trust_collections = self
            .trust_collection_repository
            .list(ListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId {
                        id: organisation.id,
                        include_inherited_collections: false,
                    }
                    .condition(),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust collections")?
            .values;

        let roles_by_local_id = group_remote_trust_collections_by_local_id(
            &local_trust_collections,
            remote_trust_collections,
        )?;

        let satisfied_by = |role: InstanceRole| {
            trust_collections.iter().all(|id| {
                roles_by_local_id
                    .get(id)
                    .is_none_or(|roles| roles.contains(&role))
            })
        };

        if !satisfied_by(InstanceRole::Wallet) && !satisfied_by(InstanceRole::Verifier) {
            return Err(OrganisationServiceError::TrustCollectionsSpanMultipleProviders);
        }

        Ok(())
    }
}
