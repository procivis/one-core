use std::collections::HashSet;

use shared_types::DidId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::{
    dto::{CreateDidRequestDTO, DidResponseDTO, GetDidListResponseDTO},
    mapper::did_from_did_request,
    validator::did_already_exists,
    DidService,
};
use crate::{
    config::validator::did::validate_did_method,
    model::{
        did::{DidListQuery, DidRelations},
        key::{KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{did::validator::validate_request_only_one_key_of_each_type, error::ServiceError},
};

impl DidService {
    /// Returns details of a did
    ///
    /// # Arguments
    ///
    /// * `id` - Did uuid
    pub async fn get_did(&self, id: &DidId) -> Result<DidResponseDTO, ServiceError> {
        let result = self
            .did_repository
            .get_did(
                id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    keys: Some(KeyRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;
        result.try_into()
    }

    /// Returns list of dids according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_did_list(
        &self,
        query: DidListQuery,
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
        validate_request_only_one_key_of_each_type(request.keys.to_owned())?;

        let did_method = self
            .did_method_provider
            .get_did_method(&request.did_method)?;

        let keys = request.keys.to_owned();

        let key_ids = HashSet::<KeyId>::from_iter(
            [
                keys.authentication,
                keys.assertion,
                keys.key_agreement,
                keys.capability_invocation,
                keys.capability_delegation,
            ]
            .concat(),
        );

        let key_id = key_ids
            .into_iter()
            .collect::<Vec<_>>()
            .first()
            .ok_or(ServiceError::IncorrectParameters)?
            .to_owned();
        let key = self
            .key_repository
            .get_key(&key_id, &KeyRelations::default())
            .await?;

        let new_did_id = DidId::from(Uuid::new_v4());

        let did_value = did_method
            .create(&new_did_id, &request.params, &Some(key.clone()))
            .await
            .map_err(ServiceError::from)?;

        if did_already_exists(&self.did_repository, &did_value).await? {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;
        let did = did_from_did_request(new_did_id, request, organisation, did_value, key, now)?;

        let did_id = self
            .did_repository
            .create_did(did)
            .await
            .map_err(ServiceError::from)?;

        Ok(did_id)
    }
}
