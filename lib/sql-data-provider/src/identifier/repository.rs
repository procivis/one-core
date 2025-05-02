use async_trait::async_trait;
use one_core::model::identifier::Identifier;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::{ActiveModelTrait, EntityTrait};
use shared_types::IdentifierId;

use super::IdentifierProvider;
use crate::entity::identifier;
use crate::mapper::to_data_layer_error;

#[async_trait]
impl IdentifierRepository for IdentifierProvider {
    async fn create(&self, request: Identifier) -> Result<IdentifierId, DataLayerError> {
        let identifier = identifier::ActiveModel::from(request)
            .insert(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        Ok(identifier.id)
    }

    async fn delete(&self, id: &IdentifierId) -> Result<(), DataLayerError> {
        identifier::Entity::delete_by_id(*id)
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;
        Ok(())
    }
}
