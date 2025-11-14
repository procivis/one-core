use one_core::model::claim_schema::ClaimSchema;
use sea_orm::{NotSet, Set};

use crate::entity::claim_schema;

impl From<ClaimSchema> for claim_schema::ActiveModel {
    fn from(value: ClaimSchema) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            key: Set(value.key),
            datatype: Set(value.data_type),
            array: Set(value.array),
            metadata: Set(value.metadata),
            credential_schema_id: NotSet,
            order: NotSet,
            required: NotSet,
        }
    }
}

impl From<claim_schema::Model> for ClaimSchema {
    fn from(value: claim_schema::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            key: value.key,
            data_type: value.datatype,
            array: value.array,
            metadata: value.metadata,
        }
    }
}
