use time::OffsetDateTime;

use crate::{
    config::validator::did::validate_did_method,
    model::did::DidValue,
    service::{did::validator::did_already_exists, error::ServiceError},
};

use super::{
    dto::{CreateDidRequestDTO, DidId, GetDidListResponseDTO, GetDidQueryDTO, GetDidResponseDTO},
    mapper::did_from_did_request,
    DidService,
};

impl DidService {
    /// Returns details of a did
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did(&self, id: &DidId) -> Result<GetDidResponseDTO, ServiceError> {
        let result = self
            .did_repository
            .get_did(id)
            .await
            .map_err(ServiceError::from)?;
        Ok(result.into())
    }

    /// Returns details of a did by value
    ///
    /// # Arguments
    ///
    /// * `value` - Did value
    pub async fn get_did_by_value(
        &self,
        value: &DidValue,
    ) -> Result<GetDidResponseDTO, ServiceError> {
        let result = self
            .did_repository
            .get_did_by_value(value)
            .await
            .map_err(ServiceError::from)?;
        Ok(result.into())
    }

    /// Returns list of dids according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_did_list(
        &self,
        query: GetDidQueryDTO,
    ) -> Result<GetDidListResponseDTO, ServiceError> {
        let result = self
            .did_repository
            .get_did_list(query)
            .await
            .map_err(ServiceError::from)?;
        Ok(result.into())
    }

    /// Creates a new did with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - did data
    /// * `did_methods` -
    pub async fn create_did(&self, request: CreateDidRequestDTO) -> Result<DidId, ServiceError> {
        validate_did_method(&request.did_method, &self.config.did)?;

        if did_already_exists(&self.did_repository, &request.did).await? {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();

        let request = did_from_did_request(request, now);

        let uuid = self
            .did_repository
            .create_did(request)
            .await
            .map_err(ServiceError::from)?;

        Ok(uuid)
    }
}
