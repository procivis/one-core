use crate::entity::key;
use crate::key::KeyProvider;
use one_core::model::key::{Key, KeyId};
use one_core::repository::error::DataLayerError;
use one_core::repository::key_repository::KeyRepository;
use sea_orm::{ActiveModelTrait, Set};

#[async_trait::async_trait]
impl KeyRepository for KeyProvider {
    async fn create_key(&self, request: Key) -> Result<KeyId, DataLayerError> {
        let credential_id = request
            .credential
            .map(|credential| credential.id.to_string());

        let organisation_id = request
            .organisation
            .ok_or(DataLayerError::MappingError)?
            .id
            .to_string();

        key::ActiveModel {
            id: Set(request.id.to_string()),
            created_date: Set(request.created_date),
            last_modified: Set(request.last_modified),
            name: Set(request.name),
            public_key: Set(request.public_key),
            private_key: Set(request.private_key),
            storage_type: Set(request.storage_type),
            key_type: Set(request.key_type),
            credential_id: Set(credential_id),
            organisation_id: Set(organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        Ok(request.id)
    }
}
