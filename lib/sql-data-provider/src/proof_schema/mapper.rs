use anyhow::anyhow;
use migration::SimpleExpr;
use one_core::model::proof_schema::{GetProofSchemaList, ProofSchema, SortableProofSchemaColumn};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::{IntoSimpleExpr, Set};

use crate::common::calculate_pages_count;
use crate::entity::proof_schema;
use crate::list_query::GetEntityColumn;

impl From<proof_schema::Model> for ProofSchema {
    fn from(value: proof_schema::Model) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            name: value.name,
            expire_duration: value.expire_duration,
            organisation: None,
            input_schemas: None,
            imported_source_url: value.imported_source_url,
        }
    }
}

impl GetEntityColumn for SortableProofSchemaColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableProofSchemaColumn::Name => proof_schema::Column::Name.into_simple_expr(),
            SortableProofSchemaColumn::CreatedDate => {
                proof_schema::Column::CreatedDate.into_simple_expr()
            }
        }
    }
}

pub(crate) fn create_list_response(
    schemas: Vec<proof_schema::Model>,
    limit: u64,
    items_count: u64,
) -> Result<GetProofSchemaList, DataLayerError> {
    Ok(GetProofSchemaList {
        values: convert_inner(schemas),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

impl TryFrom<&ProofSchema> for proof_schema::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: &ProofSchema) -> Result<Self, Self::Error> {
        Ok(Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name.to_owned()),
            imported_source_url: Set(value.imported_source_url.clone()),
            organisation_id: Set(value
                .organisation
                .as_ref()
                .ok_or(DataLayerError::Db(anyhow!(
                    "Missing organisation for proof schema {}",
                    value.id
                )))?
                .id),
            deleted_at: Set(None),
            expire_duration: Set(value.expire_duration),
        })
    }
}
