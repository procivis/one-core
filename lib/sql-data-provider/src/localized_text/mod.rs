use std::collections::HashMap;

use one_core::model::localized_text::LocalizedText;
use one_core::model::relation::{AsyncBatchLoader, BatchModelLoader, RelatedVec};
use one_core::repository::error::DataLayerError;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
use shared_types::EntityId;

use crate::entity::localized_text;
use crate::mapper::to_data_layer_error;
use crate::transaction_context::TransactionManagerImpl;

mod mapper;
mod repository;
#[cfg(test)]
mod test;

pub(crate) struct LocalizedTextProvider {
    pub db: TransactionManagerImpl,
}

pub(crate) struct LocalizedTextLoader {
    pub db: TransactionManagerImpl,
}

#[async_trait::async_trait]
impl AsyncBatchLoader<EntityId, Vec<LocalizedText>> for LocalizedTextLoader {
    async fn load(
        &self,
        ids: &[EntityId],
    ) -> Result<HashMap<EntityId, Vec<LocalizedText>>, DataLayerError> {
        let translations: Vec<localized_text::Model> = localized_text::Entity::find()
            .filter(localized_text::Column::EntityId.is_in(ids))
            .order_by_asc(localized_text::Column::Lang)
            .order_by_asc(localized_text::Column::Field)
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;

        let mut by_entity: HashMap<_, Vec<_>> = HashMap::new();
        for translation in translations {
            by_entity
                .entry(translation.entity_id)
                .or_default()
                .push(translation.into());
        }
        Ok(by_entity)
    }
}

pub(crate) fn localized_texts(
    id: EntityId,
    db: TransactionManagerImpl,
) -> RelatedVec<LocalizedText> {
    RelatedVec::new(BatchModelLoader::new([id], LocalizedTextLoader { db }).list(id))
}
