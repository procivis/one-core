use one_core::model::claim::Claim;
use one_core::repository::error::DataLayerError;
use sea_orm::Set;

use crate::entity::claim;

impl TryFrom<Claim> for claim::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Claim) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id.into()),
            credential_id: Set(value.credential_id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            value: Set(value.value.map(|val| val.as_bytes().to_vec())),
            claim_schema_id: Set(value.schema.ok_or(DataLayerError::IncorrectParameters)?.id),
            path: Set(value.path),
        })
    }
}

impl From<claim::Model> for Claim {
    fn from(value: claim::Model) -> Self {
        Self {
            id: value.id.into(),
            credential_id: value.credential_id,
            value: value
                .value
                .map(|data| String::from_utf8_lossy(&data).into_owned()),
            created_date: value.created_date,
            last_modified: value.last_modified,
            path: value.path,
            schema: None,
        }
    }
}
