use one_core::model::claim::Claim;
use one_core::model::claim_schema::ClaimSchema;
use one_core::model::relation::Related;
use sea_orm::Set;

use crate::entity::claim;

impl From<Claim> for claim::ActiveModel {
    fn from(value: Claim) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            value: Set(value.value.map(|val| val.as_bytes().to_vec())),
            claim_schema_id: Set(value.schema.id()),
            selectively_disclosable: Set(value.selectively_disclosable),
            path: Set(value.path),
        }
    }
}

pub(crate) fn claim_from_model(value: claim::Model, schema: Related<ClaimSchema>) -> Claim {
    Claim {
        id: value.id,
        value: value
            .value
            .map(|data| String::from_utf8_lossy(&data).into_owned()),
        created_date: value.created_date,
        last_modified: value.last_modified,
        path: value.path,
        selectively_disclosable: value.selectively_disclosable,
        schema,
    }
}
