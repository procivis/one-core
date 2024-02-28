use crate::entity::claim;
use one_core::{model::claim::Claim, repository::error::DataLayerError};
use sea_orm::Set;
use std::str::FromStr;
use uuid::Uuid;

impl TryFrom<Claim> for claim::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Claim) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id.to_string()),
            credential_id: Set(value.credential_id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            value: Set(value.value.as_bytes().to_owned()),
            claim_schema_id: Set(value
                .schema
                .ok_or(DataLayerError::IncorrectParameters)?
                .id
                .to_string()),
        })
    }
}

impl TryFrom<claim::Model> for Claim {
    type Error = DataLayerError;

    fn try_from(value: claim::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id)?;
        Ok(Self {
            id,
            credential_id: value.credential_id,
            value: String::from_utf8_lossy(&value.value).into_owned(),
            created_date: value.created_date,
            last_modified: value.last_modified,
            schema: None,
        })
    }
}
