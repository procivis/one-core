use autometrics::autometrics;
use one_core::{
    model::trust_entity::TrustEntity,
    repository::{error::DataLayerError, trust_entity_repository::TrustEntityRepository},
};
use sea_orm::{ActiveModelTrait, Set};
use shared_types::TrustEntityId;

use crate::{entity::trust_entity, mapper::to_data_layer_error};

use super::TrustEntityProvider;

#[autometrics]
#[async_trait::async_trait]
impl TrustEntityRepository for TrustEntityProvider {
    async fn create(&self, entity: TrustEntity) -> Result<TrustEntityId, DataLayerError> {
        let value = trust_entity::ActiveModel {
            id: Set(entity.id),
            created_date: Set(entity.created_date),
            last_modified: Set(entity.last_modified),
            entity_id: Set(entity.entity_id),
            name: Set(entity.name),
            logo: Set(entity.logo),
            website: Set(entity.website),
            terms_url: Set(entity.terms_url),
            privacy_url: Set(entity.privacy_url),
            role: Set(entity.role.into()),
            trust_anchor_id: Set(entity.trust_anchor_id),
        }
        .insert(&self.db)
        .await
        .map_err(to_data_layer_error)?;

        Ok(value.id)
    }
}
