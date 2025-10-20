use async_trait::async_trait;
use autometrics::autometrics;
use one_core::model::blob::{Blob, UpdateBlobRequest};
use one_core::repository::blob_repository::BlobRepository;
use one_core::repository::error::DataLayerError;
use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set, Unchanged};
use shared_types::BlobId;
use time::OffsetDateTime;

use crate::blob::BlobProvider;
use crate::entity::blob;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[autometrics]
#[async_trait]
impl BlobRepository for BlobProvider {
    async fn create(&self, blob: Blob) -> Result<(), DataLayerError> {
        blob::Entity::insert::<blob::ActiveModel>(blob.into())
            .exec(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;
        Ok(())
    }

    async fn get(&self, id: &BlobId) -> Result<Option<Blob>, DataLayerError> {
        let result = blob::Entity::find_by_id(id)
            .one(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?
            .map(Blob::from);

        return Ok(result);
    }

    async fn update(&self, id: &BlobId, update: UpdateBlobRequest) -> Result<(), DataLayerError> {
        let update_model = blob::ActiveModel {
            id: Unchanged(*id),
            last_modified: Set(OffsetDateTime::now_utc()),
            value: update.value.map(Set).unwrap_or_default(),
            ..Default::default()
        };

        update_model
            .update(&self.db.tx())
            .await
            .map_err(to_update_data_layer_error)?;

        Ok(())
    }

    async fn delete(&self, id: &BlobId) -> Result<(), DataLayerError> {
        blob::Entity::delete_by_id(id)
            .exec(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }

    async fn delete_many(&self, ids: &[BlobId]) -> Result<(), DataLayerError> {
        blob::Entity::delete_many()
            .filter(blob::Column::Id.is_in(ids))
            .exec(&self.db.tx())
            .await
            .map_err(to_data_layer_error)?;

        Ok(())
    }
}
