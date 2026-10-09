use std::collections::HashMap;

use shared_types::{EcosystemId, IdentifierId, OrganisationId};

use super::OrganisationService;
use super::dto::{
    CreateOrganisationRequestDTO, EcosystemInfoDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListResponseDTO, OrganisationFilterParamsDTO, UpdateOrganisationRequestDTO,
};
use super::error::OrganisationServiceError;
use super::mapper::{
    apply_configuration_update, detail_from_model, instance_detail_from_model,
    list_item_from_model, merge_ecosystems, request_to_model,
};
use super::validator::{
    validate_ecosystem_enforcement, validate_parent_organisation, validate_provider,
    validate_provider_issuer,
};
use crate::config::core_config::ConfigExt;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::identifier::{Identifier, IdentifierFilterValue, IdentifierListQuery};
use crate::model::instance::{Instance, InstanceRole};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::{
    Organisation, SortableOrganisationColumn, UpdateOrganisationRequest,
};
use crate::repository::error::DataLayerError;
use crate::service::common_dto::ListQueryDTO;
use crate::service::instance::service::provider_metadata_url;
use crate::service::managed_instance::dto::{
    EcosystemMetadataDTO, WalletProviderMetadataResponseDTO,
};
use crate::service::managed_instance::ecosystem_metadata::ecosystem_display;
use crate::service::verifier_provider::dto::VerifierProviderMetadataResponseDTO;

#[derive(Default)]
struct RemoteProviderMetadata {
    wallet: Option<WalletProviderMetadataResponseDTO>,
    verifier: Option<VerifierProviderMetadataResponseDTO>,
}

impl RemoteProviderMetadata {
    /// Whether the organisation has no linked instance, so that no provider advertises
    /// anything to it.
    fn is_empty(&self) -> bool {
        self.wallet.is_none() && self.verifier.is_none()
    }

    /// The ecosystems advertised across both providers. Both may advertise the same
    /// ecosystem, in which case the two advertisements are merged into a single entry,
    /// see [`merge_ecosystems`].
    fn ecosystems(&self) -> Vec<EcosystemMetadataDTO> {
        let advertised = self
            .wallet
            .iter()
            .flat_map(|metadata| &metadata.ecosystems)
            .chain(
                self.verifier
                    .iter()
                    .flat_map(|metadata| &metadata.ecosystems),
            )
            .cloned()
            .collect();

        merge_ecosystems(advertised)
    }
}

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
            .and_then(|list| list.require_count())
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
                    include_count: false,
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

        let (wallet_instance, verifier_instance) = self.load_instances(organisation.id).await?;
        let metadata = self
            .fetch_provider_metadata(wallet_instance.as_ref(), verifier_instance.as_ref())
            .await?;

        let ecosystems = self.ecosystems_of_organisation(&organisation, &metadata)?;
        let wallet_instance = if let Some(wallet_instance) = wallet_instance {
            instance_detail_from_model(
                wallet_instance,
                metadata.wallet.map(|m| m.feature_flags).unwrap_or_default(),
            )
            .await?
        } else {
            None
        };
        let verifier_instance = if let Some(verifier_instance) = verifier_instance {
            instance_detail_from_model(
                verifier_instance,
                metadata
                    .verifier
                    .map(|m| m.feature_flags)
                    .unwrap_or_default(),
            )
            .await?
        } else {
            None
        };

        Ok(detail_from_model(
            organisation,
            ecosystems,
            wallet_provider_issuer,
            verifier_provider_issuer,
            wallet_instance,
            verifier_instance,
        ))
    }

    /// Loads an organisation's linked wallet and verifier instance, in that order.
    async fn load_instances(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<(Option<Instance>, Option<Instance>), OrganisationServiceError> {
        let wallet_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Wallet, organisation_id)
            .await
            .error_while("getting wallet instance")?;
        let verifier_instance = self
            .instance_repository
            .get_by_role(InstanceRole::Verifier, organisation_id)
            .await
            .error_while("getting verifier instance")?;

        Ok((wallet_instance, verifier_instance))
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
            Err(DataLayerError::AlreadyExists(_)) => Err(OrganisationServiceError::AlreadyExists),
            Err(err) => Err(err.error_while("creating organisation").into()),
        }
    }

    pub async fn update_organisation(
        &self,
        request: UpdateOrganisationRequestDTO,
    ) -> Result<(), OrganisationServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&request.id)
            .await
            .error_while("getting organisation")?;

        if let Some(Some(issuer)) = &request.wallet_provider_issuer {
            validate_provider_issuer(
                &organisation,
                issuer,
                request
                    .wallet_provider
                    .as_ref()
                    .and_then(|inner| inner.as_ref()),
                self.identifier_repository.as_ref(),
                InstanceRole::Wallet,
                self.wallet_provider_directory.as_ref(),
                self.verifier_provider_directory.as_ref(),
            )
            .await?;
        }

        if let Some(Some(wallet_provider)) = &request.wallet_provider {
            validate_provider(
                &organisation,
                wallet_provider,
                InstanceRole::Wallet,
                self.organisation_repository.as_ref(),
                self.wallet_provider_directory.as_ref(),
                self.verifier_provider_directory.as_ref(),
                self.identifier_repository.as_ref(),
                request.wallet_provider_issuer.is_none(),
            )
            .await?;
        }

        if let Some(Some(issuer)) = &request.verifier_provider_issuer {
            validate_provider_issuer(
                &organisation,
                issuer,
                request
                    .verifier_provider
                    .as_ref()
                    .and_then(|inner| inner.as_ref()),
                self.identifier_repository.as_ref(),
                InstanceRole::Verifier,
                self.wallet_provider_directory.as_ref(),
                self.verifier_provider_directory.as_ref(),
            )
            .await?;
        }

        if let Some(Some(verifier_provider)) = &request.verifier_provider {
            validate_provider(
                &organisation,
                verifier_provider,
                InstanceRole::Verifier,
                self.organisation_repository.as_ref(),
                self.wallet_provider_directory.as_ref(),
                self.verifier_provider_directory.as_ref(),
                self.identifier_repository.as_ref(),
                request.verifier_provider_issuer.is_none(),
            )
            .await?;
        }

        if let Some(Some(parent_id)) = request.parent_organisation {
            validate_parent_organisation(request.id, parent_id, &*self.organisation_repository)
                .await?;
        }

        let organisation_id = request.id;

        if let Some(update) = &request.configuration {
            validate_ecosystem_enforcement(
                &organisation,
                update,
                &*self.instance_repository,
                &*self.wallet_provider_client,
                &*self.verifier_provider_client,
            )
            .await?;
        }

        let configuration = request.configuration.as_ref().map(|update| {
            apply_configuration_update(
                update.to_owned(),
                Some(organisation.configuration.to_owned()),
            )
        });
        let ecosystem_selection_changed = configuration.as_ref().is_some_and(|configuration| {
            configuration.selected_ecosystems != organisation.configuration.selected_ecosystems
        });

        let mut update_request: UpdateOrganisationRequest = request.clone().into();
        update_request.configuration = configuration;
        self.organisation_repository
            .update_organisation(&request.id, update_request)
            .await
            .error_while("updating organisation")?;

        if ecosystem_selection_changed {
            self.sync_ecosystems(organisation_id).await?;
        }

        tracing::info!("Updated organisation {organisation_id}");
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

    /// Returns the ecosystems offered to an organisation by its wallet and/or verifier
    /// provider, annotated with whether the organisation currently selected each one.
    ///
    /// An organisation without any managed instance is offered the ecosystems this core is
    /// configured for.
    fn ecosystems_of_organisation(
        &self,
        organisation: &Organisation,
        metadata: &RemoteProviderMetadata,
    ) -> Result<Vec<EcosystemInfoDTO>, OrganisationServiceError> {
        let selected_ecosystems = &organisation.configuration.selected_ecosystems;

        if metadata.is_empty() {
            // Without a linked instance there is no provider advertising ecosystems, so the
            // organisation is offered everything this core is configured for.
            return self.configured_ecosystems(selected_ecosystems);
        }

        let mut result = vec![];
        for ecosystem in metadata.ecosystems() {
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

    /// Fetches the metadata advertised to an organisation by the providers backing its
    /// linked wallet and/or verifier instance.
    async fn fetch_provider_metadata(
        &self,
        wallet_instance: Option<&Instance>,
        verifier_instance: Option<&Instance>,
    ) -> Result<RemoteProviderMetadata, OrganisationServiceError> {
        let mut result = RemoteProviderMetadata::default();

        if let Some(wallet_instance) = wallet_instance {
            result.wallet = Some(
                self.wallet_provider_client
                    .get_wallet_provider_metadata(wallet_instance.to_owned().into())
                    .await
                    .error_while("getting wallet provider metadata")?,
            );
        }

        if let Some(verifier_instance) = verifier_instance {
            let metadata_url = provider_metadata_url(
                &verifier_instance.provider_url,
                &verifier_instance.provider_name,
                InstanceRole::Verifier,
            );
            result.verifier = Some(
                self.verifier_provider_client
                    .get_verifier_provider_metadata(&metadata_url)
                    .await
                    .error_while("getting verifier provider metadata")?,
            );
        }

        Ok(result)
    }
}
