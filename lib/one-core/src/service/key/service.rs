use crate::{
    config::validator::ConfigValidationError,
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
        // TODO: ONE-868 validate_key_type(&request.key_type);
        if request.key_type != "RSA_4096" && request.key_type != "ED25519" {
            return Err(ServiceError::ConfigValidationError(
                ConfigValidationError::UnknownType(request.key_type),
            ));
        }

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await
            .map_err(ServiceError::from)?;

        let provider = self.key_provider.get_key_storage(&request.storage_type)?;
        let key = provider.generate(&request.key_type)?;

        let uuid = self
            .key_repository
            .create_key(from_create_request(request, organisation, key))
            .await
            .map_err(ServiceError::from)?;

        Ok(uuid)
    }
}
