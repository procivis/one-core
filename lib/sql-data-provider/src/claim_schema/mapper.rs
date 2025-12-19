use one_core::model::claim_schema::ClaimSchema;

use crate::entity::claim_schema;

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
