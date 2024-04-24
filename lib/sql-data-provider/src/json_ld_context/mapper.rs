use sea_orm::Set;
use url::Url;

use one_core::model::json_ld_context::JsonLdContext;
use one_core::repository::error::DataLayerError;

use crate::entity::json_ld_context;

impl From<JsonLdContext> for json_ld_context::ActiveModel {
    fn from(value: JsonLdContext) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            context: Set(value.context),
            url: Set(value.url.to_string()),
            hit_counter: Set(value.hit_counter),
        }
    }
}

impl TryFrom<json_ld_context::Model> for JsonLdContext {
    type Error = DataLayerError;

    fn try_from(value: json_ld_context::Model) -> Result<Self, Self::Error> {
        let url = Url::parse(&value.url).map_err(|_| DataLayerError::MappingError)?;

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            context: value.context,
            url,
            hit_counter: value.hit_counter,
        })
    }
}
