use std::sync::Arc;

use migration::SimpleExpr;
use one_core::model::proof_schema::{GetProofSchemaList, ProofSchema, SortableProofSchemaColumn};
use one_core::model::relation::Related;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use sea_orm::{IntoSimpleExpr, Set};

use crate::common::calculate_pages_count;
use crate::entity::proof_schema;
use crate::list_query::GetEntityColumn;

pub(super) fn into_proof_schema(
    value: proof_schema::Model,
    organisation_repository: Arc<dyn OrganisationRepository>,
) -> ProofSchema {
    ProofSchema {
        id: value.id,
        created_date: value.created_date,
        last_modified: value.last_modified,
        deleted_at: value.deleted_at,
        name: value.name,
        expire_duration: value.expire_duration,
        organisation: Related::from_organisation_id(value.organisation_id, organisation_repository),
        input_schemas: None,
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
    organisation_repository: &Arc<dyn OrganisationRepository>,
) -> Result<GetProofSchemaList, DataLayerError> {
    let values = schemas
        .into_iter()
        .map(move |item| into_proof_schema(item, organisation_repository.to_owned()))
        .collect();

    Ok(GetProofSchemaList {
        values,
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

impl From<&ProofSchema> for proof_schema::ActiveModel {
    fn from(value: &ProofSchema) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name.to_owned()),
            organisation_id: Set(*value.organisation.id()),
            deleted_at: Set(None),
            expire_duration: Set(value.expire_duration),
        }
    }
}
