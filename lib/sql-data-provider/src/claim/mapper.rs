use crate::entity::claim;
use one_core::{
    model::claim::{Claim, ClaimId},
    repository::error::DataLayerError,
};
use sea_orm::Set;
use std::{collections::HashMap, str::FromStr};
use uuid::Uuid;

impl TryFrom<Claim> for claim::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: Claim) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            value: Set(value.value),
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
        let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id,
            value: value.value,
            created_date: value.created_date,
            last_modified: value.last_modified,
            schema: None,
        })
    }
}

pub(super) fn try_to_claim_list(
    id_order: &[ClaimId],
    models: Vec<claim::Model>,
) -> Result<Vec<Claim>, DataLayerError> {
    if id_order.len() != models.len() {
        return Err(DataLayerError::RecordNotFound);
    }

    let id_to_index: HashMap<&ClaimId, usize> = id_order
        .iter()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect();

    let mut claims = models
        .into_iter()
        .map(|schema| schema.try_into())
        .collect::<Result<Vec<Claim>, DataLayerError>>()?;

    claims.sort_by(|a, b| id_to_index[&a.id].cmp(&id_to_index[&b.id]));

    Ok(claims)
}
