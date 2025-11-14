use one_core::model::credential_schema::{
    CredentialSchema, CredentialSchemaClaim, SortableCredentialSchemaColumn,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::organisation::Organisation;
use one_core::repository::error::DataLayerError;
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use one_dto_mapper::convert_inner;
use sea_orm::ActiveValue::Set;
use sea_orm::sea_query::SimpleExpr;
use sea_orm::sea_query::query::IntoCondition;
use sea_orm::{ColumnTrait, IntoSimpleExpr};
use shared_types::CredentialSchemaId;

use crate::entity::{claim_schema, credential_schema};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

impl IntoSortingColumn for SortableCredentialSchemaColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => credential_schema::Column::CreatedDate.into_simple_expr(),
            Self::Name => credential_schema::Column::Name.into_simple_expr(),
            Self::Format => credential_schema::Column::Format.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for CredentialSchemaFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(credential_schema::Column::Name, string_match)
            }
            Self::SchemaId(string_match) => {
                get_string_match_condition(credential_schema::Column::SchemaId, string_match)
            }
            Self::Formats(formats) => credential_schema::Column::Format
                .is_in(formats)
                .into_condition(),
            Self::OrganisationId(organisation_id) => get_equals_condition(
                credential_schema::Column::OrganisationId,
                organisation_id.to_string(),
            ),
            Self::CredentialSchemaIds(ids) => credential_schema::Column::Id
                .is_in(ids.iter())
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(credential_schema::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(credential_schema::Column::LastModified, value)
            }
        }
    }
}

impl TryFrom<CredentialSchema> for credential_schema::ActiveModel {
    type Error = DataLayerError;

    fn try_from(value: CredentialSchema) -> Result<Self, Self::Error> {
        let organisation_id = value.organisation.ok_or(DataLayerError::MappingError)?.id;

        Ok(Self {
            id: Set(value.id),
            deleted_at: Set(value.deleted_at),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name),
            imported_source_url: Set(value.imported_source_url),
            format: Set(value.format),
            revocation_method: Set(value.revocation_method),
            organisation_id: Set(organisation_id),
            wallet_storage_type: Set(convert_inner(value.wallet_storage_type)),
            layout_type: Set(value.layout_type.into()),
            layout_properties: Set(convert_inner(value.layout_properties)),
            schema_id: Set(value.schema_id),
            allow_suspension: Set(value.allow_suspension),
            requires_app_attestation: Set(value.requires_app_attestation),
        })
    }
}

pub(super) fn claim_schemas_to_model_vec(
    claim_schemas: Vec<CredentialSchemaClaim>,
    credential_schema_id: &CredentialSchemaId,
) -> Vec<claim_schema::ActiveModel> {
    claim_schemas
        .into_iter()
        .enumerate()
        .map(|(index, claim_schema)| claim_schema::ActiveModel {
            id: Set(claim_schema.schema.id),
            created_date: Set(claim_schema.schema.created_date),
            last_modified: Set(claim_schema.schema.last_modified),
            key: Set(claim_schema.schema.key),
            datatype: Set(claim_schema.schema.data_type),
            array: Set(claim_schema.schema.array),
            metadata: Set(claim_schema.schema.metadata),
            credential_schema_id: Set(Some(*credential_schema_id)),
            required: Set(claim_schema.required),
            order: Set(index as u32),
        })
        .collect()
}

pub(super) fn credential_schema_from_models(
    credential_schema: credential_schema::Model,
    claim_schemas: Option<Vec<CredentialSchemaClaim>>,
    organisation: Option<Organisation>,
    skip_layout_properties: bool,
) -> CredentialSchema {
    CredentialSchema {
        id: credential_schema.id,
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
        layout_properties: if skip_layout_properties {
            None
        } else {
            convert_inner(credential_schema.layout_properties)
        },
        imported_source_url: credential_schema.imported_source_url,
        schema_id: credential_schema.schema_id,
        allow_suspension: credential_schema.allow_suspension,
        requires_app_attestation: credential_schema.requires_app_attestation,
    }
}
