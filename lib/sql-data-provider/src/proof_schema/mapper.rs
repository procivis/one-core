use anyhow::anyhow;
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::proof_schema::{ProofSchema, SortableProofSchemaColumn};
use one_core::repository::error::DataLayerError;
use one_core::service::proof_schema::dto::ProofSchemaFilterValue;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{IntoCondition, Query, SimpleExpr};
use sea_orm::{ColumnTrait, IntoSimpleExpr, JoinType, Set};

use crate::entity::{credential_schema, proof_input_schema, proof_schema};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};

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

impl IntoSortingColumn for SortableProofSchemaColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::Name => proof_schema::Column::Name.into_simple_expr(),
            Self::CreatedDate => proof_schema::Column::CreatedDate.into_simple_expr(),
        }
    }
}

impl IntoFilterCondition for ProofSchemaFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> sea_orm::Condition {
        match self {
            Self::Name(string_match) => {
                get_string_match_condition(proof_schema::Column::Name, string_match)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(proof_schema::Column::OrganisationId, organisation_id)
            }
            Self::ProofSchemaIds(ids) => proof_schema::Column::Id.is_in(ids).into_condition(),
            Self::Formats(formats) => proof_schema::Column::Id
                .not_in_subquery(
                    Query::select()
                        .column(proof_input_schema::Column::ProofSchema)
                        .from(proof_input_schema::Entity)
                        .join(
                            JoinType::InnerJoin,
                            credential_schema::Entity,
                            Expr::col((credential_schema::Entity, credential_schema::Column::Id))
                                .equals((
                                    proof_input_schema::Entity,
                                    proof_input_schema::Column::CredentialSchema,
                                )),
                        )
                        .and_where(credential_schema::Column::Format.is_not_in(formats))
                        .to_owned(),
                )
                .into_condition(),
            Self::CreatedDate(value) => {
                get_comparison_condition(proof_schema::Column::CreatedDate, value)
            }
            Self::LastModified(value) => {
                get_comparison_condition(proof_schema::Column::LastModified, value)
            }
        }
    }
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
