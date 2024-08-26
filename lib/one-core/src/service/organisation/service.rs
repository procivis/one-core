use super::dto::GetOrganisationDetailsResponseDTO;
use super::validator::organisation_already_exists;
use super::OrganisationService;
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::util::history::history_event;
use dto_mapper::convert_inner;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

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

    /// Accepts optional Uuid of new organisation
    /// and returns newly created organisation uuid.
    ///
    /// # Arguments
    ///
    /// * `Option<OrganisationId>` - Optional Id for a new organisation. If not set then the
    ///   ID will be created automatically
    pub async fn create_organisation(
        &self,
        id: Option<OrganisationId>,
    ) -> Result<OrganisationId, ServiceError> {
        let now = OffsetDateTime::now_utc();

        // Check if it already exists
        if let Some(id) = id {
            if organisation_already_exists(&*self.organisation_repository, &id).await? {
                return Err(BusinessLogicError::OrganisationAlreadyExists.into());
            }
        }

        let request = Organisation {
            id: id.unwrap_or(Uuid::new_v4().into()),
            created_date: now,
            last_modified: now,
        };

        let uuid = self
            .organisation_repository
            .create_organisation(request.to_owned())
            .await?;

        let _ = self
            .history_repository
            .create_history(history_event(
                request.id,
                request.id,
                HistoryEntityType::Organisation,
                HistoryAction::Created,
            ))
            .await;

        Ok(uuid)
    }
}
