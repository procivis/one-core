use dto_mapper::convert_inner;
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
use one_core::repository::error::DataLayerError;

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
            organisation_id: Set(organisation_id),
            wallet_storage_type: Set(convert_inner(value.wallet_storage_type)),
            layout_type: Set(value.layout_type.into()),
            layout_properties: Set(convert_inner(value.layout_properties)),
            schema_type: Set(value.schema_type.into()),
            schema_id: Set(value.schema_id),
        })
    }
}

pub(super) fn entity_model_to_credential_schema(
    value: credential_schema::Model,
    skip_layout_properties: bool,
) -> Result<CredentialSchema, DataLayerError> {
    let id = Uuid::from_str(&value.id)?;

    Ok(CredentialSchema {
        id,
        deleted_at: value.deleted_at,
        created_date: value.created_date,
        last_modified: value.last_modified,
        name: value.name,
        format: value.format,
        wallet_storage_type: convert_inner(value.wallet_storage_type),
        revocation_method: value.revocation_method,
        claim_schemas: None,
        organisation: None,
        layout_type: value.layout_type.into(),
        layout_properties: if skip_layout_properties {
            None
        } else {
            convert_inner(value.layout_properties)
        },
        schema_type: value.schema_type.into(),
        schema_id: value.schema_id,
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
            .filter_map(|item| entity_model_to_credential_schema(item, true).ok())
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
            id: Set(claim_schema.schema.id),
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
                claim_schema_id: Set(claim_schema.schema.id),
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
            wallet_storage_type: convert_inner(credential_schema.wallet_storage_type),
            format: credential_schema.format,
            revocation_method: credential_schema.revocation_method,
            claim_schemas,
            organisation,
            layout_type: credential_schema.layout_type.into(),
            layout_properties: convert_inner(credential_schema.layout_properties),
            schema_type: credential_schema.schema_type.into(),
            schema_id: credential_schema.schema_id,
        })
        .ok_or(DataLayerError::MappingError)
}
