use crate::{
    model::{
        key::{KeyId, KeyRelations},
        organisation::OrganisationRelations,
    },
    service::{
        error::{EntityNotFoundError, ServiceError, ValidationError},
        key::{
            dto::{KeyRequestDTO, KeyResponseDTO},
            mapper::from_create_request,
            validator::validate_generate_request,
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
            .await?;

        let Some(key) = key else {
            return Err(EntityNotFoundError::Key(key_id.to_owned()).into());
        };

        key.try_into()
    }

    /// Generates a new random key with data provided in arguments
    ///
    /// # Arguments
    ///
    /// * `request` - key data
    pub async fn generate_key(&self, request: KeyRequestDTO) -> Result<KeyId, ServiceError> {
        validate_generate_request(&request, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &OrganisationRelations::default())
            .await?;

        let Some(organisation) = organisation else {
            return Err(EntityNotFoundError::Organisation(request.organisation_id).into());
        };

        let provider = self
            .key_provider
            .get_key_storage(&request.storage_type)
            .ok_or(ValidationError::InvalidKeyStorage(
                request.storage_type.clone(),
            ))?;

        let key_id = KeyId::new_v4();
        let key = provider.generate(&key_id, &request.key_type).await?;

        let uuid = self
            .key_repository
            .create_key(from_create_request(key_id, request, organisation, key))
            .await?;

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
        let result = self.key_repository.get_key_list(query).await?;

        Ok(result.into())
    }
}
