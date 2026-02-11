use std::collections::HashMap;

use shared_types::{IdentifierId, OrganisationId};

use super::OrganisationService;
use super::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO,
    GetOrganisationListResponseDTO, UpsertOrganisationRequestDTO,
};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::identifier::{Identifier, IdentifierFilterValue, IdentifierListQuery};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::{OrganisationListQuery, OrganisationRelations};
use crate::repository::error::DataLayerError;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::organisation::mapper::detail_from_model;
use crate::service::organisation::validator::{
    validate_wallet_provider, validate_wallet_provider_issuer,
};

impl OrganisationService {
    /// Returns all existing organisations
    pub async fn get_organisation_list(
        &self,
        query: OrganisationListQuery,
    ) -> Result<GetOrganisationListResponseDTO, ServiceError> {
        let organisations = self
            .organisation_repository
            .get_organisation_list(query)
            .await
            .error_while("getting organisations")?;

        let wallet_provider_issuers: Vec<IdentifierId> = organisations
            .values
            .iter()
            .filter_map(|organisation| {
                organisation
                    .wallet_provider_issuer
                    .as_ref()
                    .map(|issuer| *issuer)
            })
            .collect();

        let identifiers: HashMap<IdentifierId, Identifier> = if wallet_provider_issuers.is_empty() {
            Default::default()
        } else {
            self.identifier_repository
                .get_identifier_list(IdentifierListQuery {
                    filtering: Some(
                        IdentifierFilterValue::Ids(wallet_provider_issuers).condition(),
                    ),
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

                detail_from_model(organisation, wallet_provider_issuer)
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
    ) -> Result<GetOrganisationDetailsResponseDTO, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(id, &OrganisationRelations::default())
            .await
            .error_while("getting organisation")?;

        let Some(organisation) = organisation else {
            return Err(EntityNotFoundError::Organisation(*id).into());
        };

        let wallet_provider_issuer =
            if let Some(identifier_id) = &organisation.wallet_provider_issuer {
                Some(
                    self.identifier_repository
                        .get(*identifier_id, &Default::default())
                        .await
                        .error_while("getting identifier")?
                        .ok_or(ServiceError::MappingError(format!(
                            "Identifier not found: {identifier_id}"
                        )))?,
                )
            } else {
                None
            };

        Ok(detail_from_model(organisation, wallet_provider_issuer))
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
    ) -> Result<OrganisationId, ServiceError> {
        let result = self
            .organisation_repository
            .create_organisation(request.into())
            .await;

        match result {
            Ok(uuid) => {
                tracing::info!("Created organisation {}", uuid);
                Ok(uuid)
            }
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::OrganisationAlreadyExists.into())
            }
            Err(err) => Err(err.error_while("creating organisation").into()),
        }
    }

    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestDTO,
    ) -> Result<(), ServiceError> {
        if let Some(Some(issuer)) = request.wallet_provider_issuer {
            let org = self
                .organisation_repository
                .get_organisation(&request.id, &Default::default())
                .await
                .error_while("getting organisation")?;
            let id = org.as_ref().map(|org| &org.id);
            validate_wallet_provider_issuer(id, issuer, &*self.identifier_repository).await?;
        }

        if let Some(Some(wallet_provider)) = &request.wallet_provider {
            validate_wallet_provider(
                wallet_provider,
                &self.core_config,
                &*self.organisation_repository,
            )
            .await?;
        }

        // TODO: improve?
        let success_log = format!("Updated organisation {}", request.id);
        let result = self
            .organisation_repository
            .update_organisation(request.clone().into())
            .await;

        match result {
            Ok(_) => {
                tracing::info!(message = success_log);
                Ok(())
            }
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::OrganisationAlreadyExists.into())
            }
            Err(DataLayerError::RecordNotUpdated) => {
                // Organisation does not exist, create a new one instead.
                self.create_organisation(request.into()).await?;
                Ok(())
            }
            Err(err) => Err(err.error_while("updating organisation").into()),
        }
    }
}
