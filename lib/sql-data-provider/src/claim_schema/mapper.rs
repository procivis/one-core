use one_core::model::claim_schema::ClaimSchema;
use sea_orm::Set;

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
        }
    }
}
