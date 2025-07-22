use one_core::model;
use sea_orm::ActiveValue::Set;

use crate::entity;

impl From<model::blob::Blob> for entity::blob::ActiveModel {
    fn from(blob: model::blob::Blob) -> Self {
        Self {
            id: Set(blob.id),
            created_date: Set(blob.created_date),
            last_modified: Set(blob.last_modified),
            value: Set(blob.value),
            r#type: Set(blob.r#type.into()),
        }
    }
}

impl From<entity::blob::Model> for model::blob::Blob {
    fn from(value: entity::blob::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            value: value.value,
            r#type: value.r#type.into(),
        }
    }
}
