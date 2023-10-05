use crate::{
    config::{
        data_structure::{KeyAlgorithmEntity, ParamsEnum},
        validator::{
            key::{find_key_algorithm, validate_key_storage},
            ConfigValidationError,
        },
    },
    model::{key::KeyId, organisation::OrganisationRelations},
    service::{
        error::ServiceError,
        key::{dto::KeyRequestDTO, mapper::from_create_request},
    },
};

use super::KeyService;

impl KeyService {
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
        let key = provider.generate(&algorithm)?;

        let uuid = self
            .key_repository
            .create_key(from_create_request(request, organisation, key))
            .await
            .map_err(ServiceError::from)?;

        Ok(uuid)
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
