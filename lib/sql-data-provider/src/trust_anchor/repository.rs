use autometrics::autometrics;
use one_core::{
    model::trust_anchor::TrustAnchor,
    repository::{error::DataLayerError, trust_anchor_repository::TrustAnchorRepository},
};
use sea_orm::{ActiveModelTrait, EntityTrait, Set};
use shared_types::TrustAnchorId;

use crate::{entity::trust_anchor, mapper::to_data_layer_error};

use super::TrustAnchorProvider;

#[autometrics]
#[async_trait::async_trait]
impl TrustAnchorRepository for TrustAnchorProvider {
    async fn create(&self, anchor: TrustAnchor) -> Result<TrustAnchorId, DataLayerError> {
        let value = trust_anchor::ActiveModel {
            id: Set(anchor.id),
            created_date: Set(anchor.created_date),
            last_modified: Set(anchor.last_modified),
            name: Set(anchor.name),
            type_field: Set(anchor.type_field),
            publisher_reference: Set(anchor.publisher_reference),
            role: Set(anchor.role.into()),
            priority: Set(anchor.priority),
            organisation_id: Set(anchor.organisation_id),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(value.id)
    }

    async fn get(&self, id: TrustAnchorId) -> Result<Option<TrustAnchor>, DataLayerError> {
        let model = trust_anchor::Entity::find_by_id(id)
            .one(&self.db)
            .await
            .map_err(to_data_layer_error)?
            .map(Into::into);

        Ok(model)
    }
}
