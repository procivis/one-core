use async_trait::async_trait;
use one_core::model::identifier::Identifier;
use one_core::repository::error::DataLayerError;
use one_core::repository::identifier_repository::IdentifierRepository;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::IdentifierId;
use time::OffsetDateTime;

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
        let now = OffsetDateTime::now_utc();

        let identifier = identifier::ActiveModel {
            id: Unchanged(*id),
            deleted_at: Set(Some(now)),
            ..Default::default()
        };

        identifier::Entity::update(identifier)
            .filter(identifier::Column::DeletedAt.is_null())
            .exec(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        Ok(())
    }
}
