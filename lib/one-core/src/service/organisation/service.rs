use one_dto_mapper::convert_inner;
use shared_types::OrganisationId;

use super::OrganisationService;
use super::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO, UpsertOrganisationRequestDTO,
};
use crate::model::organisation::OrganisationRelations;
use crate::repository::error::DataLayerError;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};

impl OrganisationService {
    /// Returns all existing organisations
    pub async fn get_organisation_list(
        &self,
    ) -> Result<Vec<GetOrganisationDetailsResponseDTO>, ServiceError> {
        let organisations = self.organisation_repository.get_organisation_list().await?;
        Ok(convert_inner(organisations))
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
            .await?;

        let Some(organisation) = organisation else {
            return Err(EntityNotFoundError::Organisation(*id).into());
        };

        Ok(organisation.into())
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
            Ok(uuid) => Ok(uuid),
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::OrganisationAlreadyExists.into())
            }
            Err(err) => Err(err.into()),
        }
    }

    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestDTO,
    ) -> Result<(), ServiceError> {
        let result = self
            .organisation_repository
            .update_organisation(request.clone().into())
            .await;

        match result {
            Ok(_) => Ok(()),
            Err(DataLayerError::AlreadyExists) => {
                Err(BusinessLogicError::OrganisationAlreadyExists.into())
            }
            Err(DataLayerError::RecordNotUpdated) => {
                // Organisation does not exist, create a new one instead.
                self.create_organisation(request.into()).await?;
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }
}
