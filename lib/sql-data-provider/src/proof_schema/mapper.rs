use std::sync::Arc;

use one_core::model::list_filter::ListFilterCondition;
use one_core::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofSchema, SortableProofSchemaColumn,
};
use one_core::model::relation::{AsyncVecLoader, BatchModelLoader, Related, RelatedVec};
use one_core::repository::claim_schema_repository::ClaimSchemaRepository;
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::repository::error::DataLayerError;
use one_core::repository::organisation_repository::OrganisationRepository;
use one_core::service::proof_schema::dto::ProofSchemaFilterValue;
use sea_orm::prelude::Expr;
use sea_orm::sea_query::{IntoCondition, Query, SimpleExpr};
use sea_orm::{ColumnTrait, EntityTrait, IntoSimpleExpr, JoinType, QueryFilter, QueryOrder, Set};
use shared_types::ProofSchemaId;

use crate::entity::{
    credential_schema, credential_schema_format, proof_input_schema, proof_schema,
};
use crate::list_query_generic::{
    IntoFilterCondition, IntoSortingColumn, get_comparison_condition, get_equals_condition,
    get_string_match_condition,
};
use crate::transaction_context::TransactionManagerImpl;

pub(super) fn proof_schema_from_models(
    model: proof_schema::Model,
    db: &TransactionManagerImpl,
    organisation_repository: &Arc<dyn OrganisationRepository>,
    credential_schema_repository: &Arc<dyn CredentialSchemaRepository>,
    claim_schema_repository: &Arc<dyn ClaimSchemaRepository>,
) -> ProofSchema {
    ProofSchema {
        id: model.id,
        created_date: model.created_date,
        last_modified: model.last_modified,
        deleted_at: model.deleted_at,
        name: model.name,
        expire_duration: model.expire_duration as u32,
        organisation: Related::new(model.organisation_id, organisation_repository.clone()),
        input_schemas: RelatedVec::new(ProofInputSchemasLoader {
            proof_schema_id: model.id,
            db: db.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
        }),
        imported_source_url: model.imported_source_url,
        ecosystem: model.ecosystem,
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
            Self::Ecosystems(ecosystems) => proof_schema::Column::Ecosystem
                .is_in(ecosystems.iter())
                .into_condition(),
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
                        .join(
                            JoinType::InnerJoin,
                            credential_schema_format::Entity,
                            Expr::col((
                                credential_schema_format::Entity,
                                credential_schema_format::Column::CredentialSchemaId,
                            ))
                            .equals((credential_schema::Entity, credential_schema::Column::Id)),
                        )
                        .and_where(credential_schema_format::Column::Format.is_not_in(formats))
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

impl From<&ProofSchema> for proof_schema::ActiveModel {
    fn from(value: &ProofSchema) -> Self {
        Self {
            id: Set(value.id),
            created_date: Set(value.created_date),
            last_modified: Set(value.last_modified),
            name: Set(value.name.to_owned()),
            imported_source_url: Set(value.imported_source_url.clone()),
            organisation_id: Set(value.organisation.id()),
            deleted_at: Set(None),
            expire_duration: Set(value.expire_duration as i64),
            ecosystem: Set(value.ecosystem.clone()),
        }
    }
}

struct ProofInputSchemasLoader {
    proof_schema_id: ProofSchemaId,
    db: TransactionManagerImpl,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ProofInputSchema> for ProofInputSchemasLoader {
    async fn load(&self) -> Result<Vec<ProofInputSchema>, DataLayerError> {
        let mut inputs = Vec::new();

        let input_schemas = crate::entity::proof_input_schema::Entity::find()
            .filter(proof_input_schema::Column::ProofSchema.eq(self.proof_schema_id.to_string()))
            .order_by_asc(proof_input_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let schemas_loader = BatchModelLoader::new(
            input_schemas.iter().map(|model| model.credential_schema),
            self.credential_schema_repository.clone(),
        );

        for input_schema in input_schemas {
            inputs.push(ProofInputSchema {
                claim_schemas: RelatedVec::new(ProofInputClaimSchemasLoader {
                    db: self.db.clone(),
                    proof_input_schema_id: input_schema.id,
                    claim_schema_repository: self.claim_schema_repository.clone(),
                }),
                credential_schema: Related::new(
                    input_schema.credential_schema,
                    schemas_loader.clone(),
                ),
            })
        }
        Ok(inputs)
    }
}

struct ProofInputClaimSchemasLoader {
    db: TransactionManagerImpl,
    proof_input_schema_id: i64,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository>,
}

#[async_trait::async_trait]
impl AsyncVecLoader<ProofInputClaimSchema> for ProofInputClaimSchemasLoader {
    async fn load(&self) -> Result<Vec<ProofInputClaimSchema>, DataLayerError> {
        let input_schema_claim_schema = crate::entity::proof_input_claim_schema::Entity::find()
            .filter(
                crate::entity::proof_input_claim_schema::Column::ProofInputSchemaId
                    .eq(self.proof_input_schema_id),
            )
            .order_by_asc(crate::entity::proof_input_claim_schema::Column::Order)
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::Db(e.into()))?;

        let claim_schema_ids = input_schema_claim_schema
            .iter()
            .map(|item| item.claim_schema_id)
            .collect();

        let claim_schemas = self
            .claim_schema_repository
            .get_claim_schema_list(claim_schema_ids)
            .await?;

        Ok(input_schema_claim_schema
            .into_iter()
            .zip(claim_schemas)
            .map(|(model, schema)| ProofInputClaimSchema {
                schema,
                required: model.required,
                order: model.order as u32,
            })
            .collect())
    }
}
