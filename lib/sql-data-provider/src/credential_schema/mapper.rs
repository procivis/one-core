use sea_orm::sea_query::SimpleExpr;
use sea_orm::ActiveValue::Set;
use sea_orm::IntoSimpleExpr;
use std::str::FromStr;

use uuid::Uuid;

use crate::common::calculate_pages_count;

use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, GetCredentialSchemaList,
    SortableCredentialSchemaColumn,
};
use one_core::model::organisation::Organisation;
use one_core::{model::claim_schema::ClaimSchemaId, repository::error::DataLayerError};

use crate::entity::{claim_schema, credential_schema, credential_schema_claim_schema};
use crate::list_query::GetEntityColumn;

impl TryFrom<CredentialSchema> for credential_schema::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = match value.organisation {
            None => Err(DataLayerError::MappingError),
            Some(value) => Ok(value.id),
        }?;

        Ok(Self {
            id: Set(value.id.to_string()),
            deleted_at: Set(value.deleted_at),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            format: Set(value.format),
            revocation_method: Set(value.revocation_method),
            organisation_id: Set(organisation_id.to_string()),
        })
    }
}

impl TryFrom<credential_schema_claim_schema::Model> for ClaimSchemaId {
    type Error = DataLayerError;

    fn try_from(value: credential_schema_claim_schema::Model) -> Result<Self, Self::Error> {
        Ok(Uuid::from_str(&value.claim_schema_id)?)
    }
}

fn entity_model_to_credential_schema(
    value: credential_schema::Model,
    organisation: Option<Organisation>,
) -> Result<CredentialSchema, DataLayerError> {
    let id = Uuid::from_str(&value.id)?;
    let _organisation_id = Uuid::from_str(&value.organisation_id)?;

    Ok(CredentialSchema {
        id,
        deleted_at: value.deleted_at,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        revocation_method: value.revocation_method,
        claim_schemas: None,
        organisation,
    })
}

pub(crate) fn create_list_response(
    credential_schemas: Vec<credential_schema::Model>,
    limit: u64,
    items_count: u64,
) -> GetCredentialSchemaList {
    GetCredentialSchemaList {
        values: credential_schemas
            .into_iter()
            .filter_map(|item| entity_model_to_credential_schema(item, None).ok())
            .collect(),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    }
}

impl GetEntityColumn for SortableCredentialSchemaColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableCredentialSchemaColumn::Name => {
                credential_schema::Column::Name.into_simple_expr()
            }
            SortableCredentialSchemaColumn::Format => {
                credential_schema::Column::Format.into_simple_expr()
            }
            SortableCredentialSchemaColumn::CreatedDate => {
                credential_schema::Column::CreatedDate.into_simple_expr()
            }
        }
    }
}

pub(super) fn claim_schemas_to_model_vec(
    claim_schemas: Vec<CredentialSchemaClaim>,
) -> Vec<claim_schema::ActiveModel> {
    claim_schemas
        .into_iter()
        .map(|claim_schema| claim_schema::ActiveModel {
            id: Set(claim_schema.schema.id.to_string()),
            created_date: Set(claim_schema.schema.created_date),
            last_modified: Set(claim_schema.schema.last_modified),
            key: Set(claim_schema.schema.key),
            datatype: Set(claim_schema.schema.data_type),
        })
        .collect()
}

pub(super) fn claim_schemas_to_relations(
    claim_schemas: &[CredentialSchemaClaim],
    credential_schema_id: &str,
) -> Vec<credential_schema_claim_schema::ActiveModel> {
    claim_schemas
        .iter()
        .enumerate()
        .map(
            |(i, claim_schema)| credential_schema_claim_schema::ActiveModel {
                claim_schema_id: Set(claim_schema.schema.id.to_string()),
                credential_schema_id: Set(credential_schema_id.to_string()),
                required: Set(claim_schema.required),
                order: Set(i as u32),
            },
        )
        .collect()
}

pub(crate) fn credential_schema_from_models(
    credential_schema: credential_schema::Model,
    claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    organisation: Option<Organisation>,
) -> Result<CredentialSchema, DataLayerError> {
    Uuid::from_str(&credential_schema.id)
        .ok()
        .map(|id| CredentialSchema {
            id,
            deleted_at: credential_schema.deleted_at,
            created_date: credential_schema.created_date,
            last_modified: credential_schema.last_modified,
            name: credential_schema.name,
            format: credential_schema.format,
            revocation_method: credential_schema.revocation_method,
            claim_schemas,
            organisation,
        })
        .ok_or(DataLayerError::MappingError)
}
