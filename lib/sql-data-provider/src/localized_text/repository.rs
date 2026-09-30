use entity::localized_text::{Column, Entity};
use one_core::model::localized_text::LocalizedText;
use one_core::repository::error::DataLayerError;
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::OnConflict;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use shared_types::EntityId;

use crate::entity;
use crate::entity::localized_text::ActiveModel;
use crate::localized_text::LocalizedTextProvider;
use crate::localized_text::mapper::deduplicate_localized_texts;
use crate::mapper::{to_data_layer_error, to_update_data_layer_error};

#[async_trait::async_trait]
impl LocalizedTextRepository for LocalizedTextProvider {
    async fn upsert(&self, localized_text: LocalizedText) -> Result<(), DataLayerError> {
        let model = ActiveModel::from(localized_text);
        Entity::insert(model)
            .on_conflict(update_on_conflict())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn upsert_many(&self, localized_text: Vec<LocalizedText>) -> Result<(), DataLayerError> {
        let model: Vec<ActiveModel> = convert_inner(deduplicate_localized_texts(localized_text));
        Entity::insert_many(model)
            .on_conflict(update_on_conflict())
            .exec(&self.db)
            .await
            .map_err(to_update_data_layer_error)?;
        Ok(())
    }

    async fn get(&self, id: &EntityId) -> Result<Vec<LocalizedText>, DataLayerError> {
        let models = Entity::find()
            .filter(Column::EntityId.eq(id))
            .all(&self.db)
            .await
            .map_err(to_data_layer_error)?;
        Ok(convert_inner(models))
    }
}

fn update_on_conflict() -> OnConflict {
    OnConflict::columns([Column::EntityId, Column::Lang, Column::Field])
        .update_column(Column::LastModified)
        .update_column(Column::Value)
        .to_owned()
}
