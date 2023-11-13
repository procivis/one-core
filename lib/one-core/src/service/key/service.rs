use crate::{
    config::{
        data_structure::{KeyAlgorithmEntity, ParamsEnum},
        validator::{
            key::{find_key_algorithm, validate_key_storage},
            ConfigValidationError,
        },
    },
    model::{
        key::{KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{
        error::ServiceError,
        key::{
            dto::{KeyRequestDTO, KeyResponseDTO},
            mapper::from_create_request,
        },
    },
};

use super::{
    dto::{GetKeyListResponseDTO, GetKeyQueryDTO},
    KeyService,
};

impl KeyService {
    /// Returns details of a key
    ///
    /// # Arguments
    ///
    /// * `KeyId` - Id of an existing key
    pub async fn get_key(&self, key_id: &KeyId) -> Result<KeyResponseDTO, ServiceError> {
        let key = self
            .key_repository
            .get_key(
                key_id,
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;

        key.try_into()
    }

    /// Generates a new random key with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - key data
    pub async fn generate_key(&self, request: KeyRequestDTO) -> Result<KeyId, ServiceError> {
        let algorithm_entity = find_key_algorithm(&request.key_type, &self.config.key_algorithm)?;
        validate_key_storage(&request.storage_type, &self.config.key_storage)?;

        let algorithm = get_algorithm_from_storage(algorithm_entity)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await
            .map_err(ServiceError::from)?;

        let provider = self.key_provider.get_key_storage(&request.storage_type)?;
        let key = provider.generate(&algorithm).await?;

        let uuid = self
            .key_repository
            .create_key(from_create_request(request, organisation, key))
            .await
            .map_err(ServiceError::from)?;

        Ok(uuid)
    }

    /// Returns list of keys according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_key_list(
        &self,
        query: GetKeyQueryDTO,
    ) -> Result<GetKeyListResponseDTO, ServiceError> {
        let result = self
            .key_repository
            .get_key_list(query)
            .await
            .map_err(ServiceError::from)?;

        Ok(result.into())
    }
}

fn get_algorithm_from_storage(
    algorithm_entity: &KeyAlgorithmEntity,
) -> Result<String, ConfigValidationError> {
    let params = algorithm_entity
        .params
        .as_ref()
        .ok_or(ConfigValidationError::KeyNotFound(
            "params is None".to_string(),
        ))?;
    match params {
        ParamsEnum::Parsed(value) => Ok(value.algorithm.value.to_owned()),
        _ => Err(ConfigValidationError::UnparsedParameterTree),
    }
}
