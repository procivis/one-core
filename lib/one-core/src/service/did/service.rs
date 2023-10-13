use std::collections::{HashMap, HashSet};

use time::OffsetDateTime;

use crate::{
    config::validator::did::validate_did_method,
    model::{
        did::DidRelations,
        key::{Key, KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{did::validator::did_already_exists, error::ServiceError},
};

use super::{
    dto::{CreateDidRequestDTO, DidId, DidResponseDTO, GetDidListResponseDTO, GetDidQueryDTO},
    mapper::did_from_did_request,
    DidService,
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

        // TODO: proper did generation
        let did_value = format!("did:{}:{}", request.did_method, request.name);

        if did_already_exists(&self.did_repository, &did_value).await? {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let mut key_map: HashMap<KeyId, Key> = HashMap::default();
        let keys = request.keys.to_owned();
        for key_id in HashSet::<KeyId>::from_iter(
            [
                keys.authentication,
                keys.assertion,
                keys.key_agreement,
                keys.capability_invocation,
                keys.capability_delegation,
            ]
            .concat()
            .into_iter(),
        ) {
            let key = self
                .key_repository
                .get_key(&key_id, &KeyRelations::default())
                .await?;
            key_map.insert(key_id, key);
        }

        let request = did_from_did_request(request, organisation, did_value, key_map, now)?;

        self.did_repository
            .create_did(request)
            .await
            .map_err(ServiceError::from)
    }
}
