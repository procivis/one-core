use std::{collections::HashMap, str::FromStr};

use one_core::{model::claim_schema::ClaimSchema, repository::error::DataLayerError};
use sea_orm::Set;
use uuid::Uuid;

use crate::entity::claim_schema;

impl From<ClaimSchema> for claim_schema::ActiveModel {
    fn from(value: ClaimSchema) -> Self {
        Self {
            id: Set(value.id.to_string()),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            key: Set(value.key),
            datatype: Set(value.data_type),
        }
    }
}

impl TryFrom<claim_schema::Model> for ClaimSchema {
    type Error = DataLayerError;

    fn try_from(value: claim_schema::Model) -> Result<Self, Self::Error> {
        let id = Uuid::from_str(&value.id).map_err(|_| DataLayerError::MappingError)?;
        Ok(Self {
            id,
            key: value.key,
            data_type: value.datatype,
            created_date: value.created_date,
            last_modified: value.last_modified,
        })
    }
}

pub(super) fn to_claim_schema_list(
    ids: &[Uuid],
    models: Vec<claim_schema::Model>,
) -> Result<Vec<ClaimSchema>, DataLayerError> {
    if ids.len() > models.len() {
        return Err(DataLayerError::RecordNotFound);
    }

    let id_to_index: HashMap<&Uuid, usize> = ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect();

    let mut schemas: Vec<ClaimSchema> = models
        .into_iter()
        .filter_map(|schema| schema.try_into().ok())
        .collect();

    schemas.sort_by(|a, b| id_to_index[&a.id].cmp(&id_to_index[&b.id]));

    Ok(schemas)
}
