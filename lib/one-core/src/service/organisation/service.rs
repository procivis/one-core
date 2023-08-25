use time::OffsetDateTime;
use uuid::Uuid;

use crate::{model::organisation::Organisation, service::error::ServiceError};

use super::{
    dto::{GetOrganisationDetailsResponseDTO, OrganisationId},
    validator::organisation_already_exists,
    OrganisationService,
};

impl OrganisationService {
    /// Returns all existing organisations
    pub async fn get_organisation_list(
        &self,
    ) -> Result<Vec<GetOrganisationDetailsResponseDTO>, ServiceError> {
        let result = self
            .organisation_repository
            .get_organisation_list()
            .await
            .map_err(ServiceError::from)?;

        Ok(result
            .into_iter()
            .filter_map(|v| v.try_into().ok())
            .collect())
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
        let result = self
            .organisation_repository
            .get_organisation(id)
            .await
            .map_err(ServiceError::from)?;
        Ok(result.into())
    }

    /// Accepts optional Uuid of new organisation
    /// and returns newly created organisation uuid.
    ///
    /// # Arguments
    ///
    /// * `Option<OrganisationId>` - Optional Id for a new organisation. If not set then the
    /// ID will be created automatically
    pub async fn create_organisation(
        &self,
        id: Option<OrganisationId>,
    ) -> Result<OrganisationId, ServiceError> {
        let now = OffsetDateTime::now_utc();

        // Check if it already exists
        if let Some(id) = id {
            if organisation_already_exists(&self.organisation_repository, &id).await? {
                return Err(ServiceError::AlreadyExists);
            }
        }

        let request = Organisation {
            id: id.unwrap_or(Uuid::new_v4()),
            created_date: now,
            last_modified: now,
        };

        let uuid = self
            .organisation_repository
            .create_organisation(request)
            .await
            .map_err(ServiceError::from)?;

        Ok(uuid)
    }
}
