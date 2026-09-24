use std::collections::HashSet;

use futures::future::try_join_all;
use migration::supported_db_type::SupportedDbType;
use one_core::model::history::{
    HistoryAction, HistoryEntityType, HistoryFilterValue, HistorySearchEnum, HistorySource,
    IssuerStatsQuery, SortableHistoryColumn, SortableIssuerStatisticsColumn,
    SortableSystemInteractionStatisticsColumn, SortableSystemManagementStatisticsColumn,
    SortableVerifierStatisticsColumn, StatsBySchemaFilterValue, SystemInteractionStatsQuery,
    SystemManagementStatsQuery, SystemStatsFilterValue, VerifierStatsQuery,
};
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType, ValueComparison,
};
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{
    Alias, CaseStatement, ColumnName, ColumnRef, Condition, Expr, Func, IntoColumnRef,
    IntoCondition, IntoIden, IntoTableRef, Query, SelectStatement, SimpleExpr,
};
use sea_orm::{
    ActiveEnum, ColumnTrait, ConnectionTrait, EntityTrait, ExprTrait, FromQueryResult, JoinType,
    Order, QueryFilter, QuerySelect, QueryTrait, RelationTrait,
};
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, IdentifierId, OrganisationId, ProofId,
    ProofSchemaId, TrustCollectionId,
};
use time::OffsetDateTime;

use crate::entity::{
    claim, claim_schema, credential, credential_schema, did, history, identifier, proof,
    proof_claim, proof_input_claim_schema, proof_input_schema, proof_schema,
    trust_list_subscription,
};
use crate::history::mapper::{ceil, floor};
use crate::history::model::{EntityIdRow, TimeResolution};
use crate::list_query_generic::{
    ColumnSortingBehavior, IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    SelectWithListQuery, get_blob_match_condition, get_comparison_condition,
};

const ENTITY_ID: &str = "entity_id";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PreprocessedHistoryFilterValue {
    EntityTypes(Vec<HistoryEntityType>),
    EntityIds(Vec<EntityId>),
    Actions(Vec<HistoryAction>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    IdentifierId(IdentifierId),
    OrganisationIds(Vec<OrganisationId>),
    ProofId(ProofId),
    Users(Vec<String>),
    Sources(Vec<HistorySource>),
    Target(String),
}

impl ListFilterValue for PreprocessedHistoryFilterValue {}

impl IntoSortingColumn for SortableHistoryColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CreatedDate => ColumnSortingBehavior::default(history::Column::CreatedDate),
            Self::Action => ColumnSortingBehavior::default(history::Column::Action),
            Self::EntityType => ColumnSortingBehavior::default(history::Column::EntityType),
            Self::Source => ColumnSortingBehavior::default(history::Column::Source),
            Self::User => ColumnSortingBehavior::case_insensitive(history::Column::User),
            Self::OrganisationId => ColumnSortingBehavior::default(history::Column::OrganisationId),
        }
    }
}

fn credential_id_related_subqueries(credential_id: CredentialId) -> Vec<SelectStatement> {
    vec![
        select_proof_id_from_proof_claim_to_claim_join()
            .cond_where(
                proof_claim::Column::CredentialId.eq(credential_id).or(
                    proof_claim::Column::CredentialId.in_subquery(
                        Query::select()
                            .column(credential::Column::Id)
                            .from(credential::Entity)
                            .and_where(credential::Column::ParentId.eq(credential_id))
                            .and_where(
                                credential::Column::Role.eq(credential::CredentialRole::Holder),
                            )
                            .to_owned(),
                    ),
                ),
            )
            .to_owned(),
    ]
}

fn credential_schema_id_related_subqueries(
    credential_schema_id: CredentialSchemaId,
) -> Vec<SelectStatement> {
    let match_condition = credential_schema::Column::Id.eq(credential_schema_id);
    vec![
        select_proof_id_from_proof_to_cred_schema_joins()
            .cond_where(match_condition.clone())
            .to_owned(),
        select_credential_id_from_credential_to_schema_join()
            .cond_where(match_condition)
            .to_owned(),
    ]
}

fn select_credential_id_from_credential_to_schema_join() -> SelectStatement {
    Query::select()
        .expr_as(credential::Column::Id.into_expr(), ENTITY_ID)
        .from(credential::Entity)
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(Expr::col(
                (credential_schema::Entity, credential_schema::Column::Id),
            )),
        )
        .to_owned()
}

fn select_proof_id_from_proof_to_cred_schema_joins() -> SelectStatement {
    select_proof_id_from_proof_claim_to_claim_join()
        .inner_join(
            credential::Entity,
            Expr::col((proof_claim::Entity, proof_claim::Column::CredentialId))
                .eq(Expr::col((credential::Entity, credential::Column::Id))),
        )
        .inner_join(
            credential_schema::Entity,
            Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(Expr::col(
                (credential_schema::Entity, credential_schema::Column::Id),
            )),
        )
        .to_owned()
}

fn select_proof_id_from_proof_claim_to_claim_join() -> SelectStatement {
    Query::select()
        .expr_as(proof_claim::Column::ProofId.into_expr(), ENTITY_ID)
        .from(proof_claim::Entity)
        .inner_join(
            claim::Entity,
            Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                .eq(Expr::col((claim::Entity, claim::Column::Id))),
        )
        .to_owned()
}

fn proof_schema_id_related_subqueries(proof_schema_id: ProofSchemaId) -> Vec<SelectStatement> {
    vec![
        Query::select()
            .expr_as(proof::Column::Id.into_expr(), ENTITY_ID)
            .from(proof::Entity)
            .inner_join(
                proof_schema::Entity,
                Expr::col((proof_schema::Entity, proof_schema::Column::Id))
                    .eq(Expr::col((proof::Entity, proof::Column::ProofSchemaId))),
            )
            .cond_where(proof_schema::Column::Id.eq(proof_schema_id))
            .to_owned(),
    ]
}

fn trust_collection_id_related_subqueries(
    trust_collection_id: TrustCollectionId,
) -> Vec<SelectStatement> {
    vec![
        Query::select()
            .expr_as(trust_list_subscription::Column::Id.into_expr(), ENTITY_ID)
            .from(trust_list_subscription::Entity)
            .cond_where(trust_list_subscription::Column::TrustCollectionId.eq(trust_collection_id))
            .to_owned(),
    ]
}

impl IntoFilterCondition for PreprocessedHistoryFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::EntityTypes(entity_types) => history::Column::EntityType
                .is_in(
                    entity_types
                        .into_iter()
                        .map(history::HistoryEntityType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::EntityIds(entity_ids) => {
                history::Column::EntityId.is_in(entity_ids).into_condition()
            }
            Self::Actions(actions) => history::Column::Action
                .is_in::<history::HistoryAction, _>(convert_inner(actions))
                .into_condition(),
            Self::CreatedDate(date_comparison) => {
                get_comparison_condition(history::Column::CreatedDate, date_comparison)
            }
            Self::IdentifierId(identifier_id) => credential::Column::IssuerIdentifierId
                .eq(identifier_id)
                .or(credential::Column::HolderIdentifierId.eq(identifier_id))
                .or(proof::Column::VerifierIdentifierId.eq(identifier_id))
                .or(history::Column::EntityId
                    .eq(identifier_id)
                    .and(history::Column::EntityType.eq(history::HistoryEntityType::Identifier)))
                .into_condition(),
            Self::OrganisationIds(organisation_ids) => history::Column::OrganisationId
                .is_in(organisation_ids)
                .into_condition(),
            Self::ProofId(proof_id) => history::Column::EntityId
                .eq(proof_id)
                .and(history::Column::EntityType.eq(history::HistoryEntityType::Proof))
                .or(history::Column::Target
                    .eq(proof_id)
                    .and(history::Column::EntityType.eq(history::HistoryEntityType::Notification)))
                .into_condition(),
            Self::Users(users) => history::Column::User.is_in(users).into_condition(),
            Self::Sources(sources) => history::Column::Source
                .is_in::<history::HistorySource, _>(convert_inner(sources))
                .into_condition(),
            Self::Target(target) => history::Column::Target.eq(target).into_condition(),
        }
    }
}

fn select_holder_parent_ids_for_claims() -> SelectStatement {
    Query::select()
        .expr_as(credential::Column::ParentId.into_expr(), ENTITY_ID)
        .from(claim::Entity)
        .inner_join(
            credential::Entity,
            Expr::col((claim::Entity, claim::Column::CredentialId))
                .equals((credential::Entity, credential::Column::Id)),
        )
        .and_where(credential::Column::Role.eq(credential::CredentialRole::Holder))
        .and_where(credential::Column::ParentId.is_not_null())
        .to_owned()
}

fn search_query_subqueries(
    search_text: String,
    search_type: HistorySearchEnum,
) -> Vec<SelectStatement> {
    match search_type {
        HistorySearchEnum::All => search_all_subqueries(search_text),
        HistorySearchEnum::ClaimName => vec![
            select_holder_parent_ids_for_claims()
                .inner_join(
                    claim_schema::Entity,
                    Expr::col((claim_schema::Entity, claim_schema::Column::Id))
                        .equals((claim::Entity, claim::Column::ClaimSchemaId)),
                )
                .cond_where(claim_schema::Column::Key.contains(search_text.to_owned()))
                .to_owned(),
            Query::select()
                .expr_as(claim::Column::CredentialId.into_expr(), ENTITY_ID)
                .from(claim::Entity)
                .inner_join(
                    claim_schema::Entity,
                    Expr::col((claim_schema::Entity, claim_schema::Column::Id))
                        .eq(Expr::col((claim::Entity, claim::Column::ClaimSchemaId))),
                )
                .cond_where(claim_schema::Column::Key.contains(search_text.to_owned()))
                .to_owned(),
            Query::select()
                .expr_as(proof::Column::Id.into_expr(), ENTITY_ID)
                .from(claim::Entity)
                .inner_join(
                    claim_schema::Entity,
                    Expr::col((claim_schema::Entity, claim_schema::Column::Id))
                        .eq(Expr::col((claim::Entity, claim::Column::ClaimSchemaId))),
                )
                .inner_join(
                    proof_input_claim_schema::Entity,
                    Expr::col((claim::Entity, claim::Column::ClaimSchemaId)).eq(Expr::col((
                        proof_input_claim_schema::Entity,
                        proof_input_claim_schema::Column::ClaimSchemaId,
                    ))),
                )
                .inner_join(
                    proof_input_schema::Entity,
                    Expr::col((proof_input_schema::Entity, proof_input_schema::Column::Id)).eq(
                        Expr::col((
                            proof_input_claim_schema::Entity,
                            proof_input_claim_schema::Column::ProofInputSchemaId,
                        )),
                    ),
                )
                .inner_join(
                    proof::Entity,
                    Expr::col((
                        proof_input_schema::Entity,
                        proof_input_schema::Column::ProofSchema,
                    ))
                    .eq(Expr::col((proof::Entity, proof::Column::ProofSchemaId))),
                )
                .cond_where(claim_schema::Column::Key.contains(search_text))
                .to_owned(),
        ],
        HistorySearchEnum::ClaimValue => vec![
            select_holder_parent_ids_for_claims()
                .cond_where(get_blob_match_condition(
                    claim::Column::Value,
                    StringMatch {
                        r#match: StringMatchType::Contains,
                        value: search_text.to_owned(),
                    },
                    255,
                ))
                .to_owned(),
            Query::select()
                .expr_as(claim::Column::CredentialId.into_expr(), ENTITY_ID)
                .from(claim::Entity)
                .cond_where(get_blob_match_condition(
                    claim::Column::Value,
                    StringMatch {
                        r#match: StringMatchType::Contains,
                        value: search_text.to_owned(),
                    },
                    255,
                ))
                .to_owned(),
            Query::select()
                .expr_as(proof::Column::Id.into_expr(), ENTITY_ID)
                .from(claim::Entity)
                .inner_join(
                    proof_input_claim_schema::Entity,
                    Expr::col((claim::Entity, claim::Column::ClaimSchemaId)).eq(Expr::col((
                        proof_input_claim_schema::Entity,
                        proof_input_claim_schema::Column::ClaimSchemaId,
                    ))),
                )
                .inner_join(
                    proof_input_schema::Entity,
                    Expr::col((proof_input_schema::Entity, proof_input_schema::Column::Id)).eq(
                        Expr::col((
                            proof_input_claim_schema::Entity,
                            proof_input_claim_schema::Column::ProofInputSchemaId,
                        )),
                    ),
                )
                .inner_join(
                    proof::Entity,
                    Expr::col((
                        proof_input_schema::Entity,
                        proof_input_schema::Column::ProofSchema,
                    ))
                    .eq(Expr::col((proof::Entity, proof::Column::ProofSchemaId))),
                )
                .cond_where(get_blob_match_condition(
                    claim::Column::Value,
                    StringMatch {
                        r#match: StringMatchType::Contains,
                        value: search_text,
                    },
                    255,
                ))
                .to_owned(),
        ],
        HistorySearchEnum::CredentialSchemaName => credential_schema_name_search_subqueries(
            credential_schema::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::IssuerDid => search_query_identifier_subqueries(
            credential::Column::Id,
            credential::Column::IssuerIdentifierId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::IssuerName => search_query_identifier_subqueries(
            credential::Column::Id,
            credential::Column::IssuerIdentifierId,
            did::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::VerifierDid => search_query_identifier_subqueries(
            proof::Column::Id,
            proof::Column::VerifierIdentifierId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::VerifierName => search_query_identifier_subqueries(
            proof::Column::Id,
            proof::Column::VerifierIdentifierId,
            did::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::ProofSchemaName => vec![
            proof_schema::Entity::find()
                .filter(proof_schema::Column::Name.contains(search_text))
                .select_only()
                .column_as(proof_schema::Column::Id, "entity_id")
                .into_query(),
        ],
    }
}

fn search_query_identifier_subqueries(
    entity_id_column: impl ColumnTrait,
    identifier_id_column: impl ColumnTrait + IntoIden,
    condition: impl IntoCondition + Clone,
) -> Vec<SelectStatement> {
    vec![
        Query::select()
            .expr_as(entity_id_column.into_expr(), ENTITY_ID)
            .from(entity_id_column.entity_name().into_table_ref())
            .inner_join(
                identifier::Entity,
                Expr::col(ColumnRef::Column(ColumnName(
                    Some(identifier_id_column.entity_name().into()),
                    identifier_id_column.into_iden(),
                )))
                .eq(Expr::col((identifier::Entity, identifier::Column::Id))),
            )
            .inner_join(
                did::Entity,
                Expr::col((identifier::Entity, identifier::Column::DidId))
                    .eq(Expr::col((did::Entity, did::Column::Id))),
            )
            .cond_where(condition.to_owned())
            .to_owned(),
        Query::select()
            .expr_as(did::Column::Id.into_expr(), ENTITY_ID)
            .from(did::Entity)
            .inner_join(
                identifier::Entity,
                Expr::col((did::Entity, did::Column::Id))
                    .eq(Expr::col((identifier::Entity, identifier::Column::DidId))),
            )
            .inner_join(
                identifier_id_column.entity_name(),
                Expr::col(ColumnRef::Column(ColumnName(
                    Some(identifier_id_column.entity_name().into()),
                    identifier_id_column.into_iden(),
                )))
                .eq(Expr::col((identifier::Entity, identifier::Column::Id))),
            )
            .cond_where(condition)
            .to_owned(),
    ]
}

fn credential_schema_name_search_subqueries(
    credential_schema_match_condition: SimpleExpr,
) -> Vec<SelectStatement> {
    vec![
        select_proof_id_from_proof_to_cred_schema_joins()
            .cond_where(credential_schema_match_condition.to_owned())
            .to_owned(),
        select_credential_id_from_credential_to_schema_join()
            .cond_where(credential_schema_match_condition.to_owned())
            .to_owned(),
        Query::select()
            .expr_as(credential_schema::Column::Id.into_expr(), ENTITY_ID)
            .from(credential_schema::Entity)
            .cond_where(credential_schema_match_condition)
            .to_owned(),
    ]
}

impl IntoJoinRelations for PreprocessedHistoryFilterValue {
    fn get_join(&self) -> Vec<JoinRelation> {
        match self {
            Self::IdentifierId(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: history::Relation::MentionedCredential.def(),
                        alias: None,
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: history::Relation::MentionedProof.def(),
                        alias: None,
                    },
                ]
            }
            _ => vec![],
        }
    }
}

fn search_all_subqueries(search_text: String) -> Vec<SelectStatement> {
    [
        HistorySearchEnum::ClaimName,
        HistorySearchEnum::ClaimValue,
        HistorySearchEnum::CredentialSchemaName,
        HistorySearchEnum::IssuerDid,
        HistorySearchEnum::IssuerName,
        HistorySearchEnum::VerifierDid,
        HistorySearchEnum::VerifierName,
    ]
    .into_iter()
    .flat_map(|entry| search_query_subqueries(search_text.to_owned(), entry))
    .collect()
}

/// Executes the related-entity subqueries of `filter` up-front, returning an equivalent filter in
/// which every subquery-backed leaf is replaced by a concrete
/// [`PreprocessedHistoryFilterValue::EntityIds`] list.
///
/// Building the list query with `entity_id IN (subquery)` conditions forces MySQL into a full
/// organisation scan: the `IN (subquery)` branch can't participate in `index_merge`, so the
/// optimizer uses the `organisation_id`/`created_date` index only for the `ORDER BY … LIMIT` and
/// filters every row of the organisation. Plain `entity_id IN (id, …)` lists let it use
/// `index_merge` on the `entity_id` index instead.
pub(super) async fn preprocess_history_filter(
    db: &impl ConnectionTrait,
    filter: ListFilterCondition<HistoryFilterValue>,
) -> Result<ListFilterCondition<PreprocessedHistoryFilterValue>, DataLayerError> {
    let prepared_filter = match filter {
        ListFilterCondition::And(conditions) => {
            let mut prepared = Vec::with_capacity(conditions.len());
            for condition in conditions {
                prepared.push(Box::pin(preprocess_history_filter(db, condition)).await?);
            }
            ListFilterCondition::And(prepared)
        }
        ListFilterCondition::Or(conditions) => {
            let mut prepared = Vec::with_capacity(conditions.len());
            for condition in conditions {
                prepared.push(Box::pin(preprocess_history_filter(db, condition)).await?);
            }
            ListFilterCondition::Or(prepared)
        }
        ListFilterCondition::Value(value) => preresolve_expensive_relations(db, value).await?,
    };
    Ok(prepared_filter)
}

/// Preresolve expensive subqueries into easier conditions so that the history table can be filtered more efficiently.
async fn preresolve_expensive_relations(
    db: &impl ConnectionTrait,
    value: HistoryFilterValue,
) -> Result<ListFilterCondition<PreprocessedHistoryFilterValue>, DataLayerError> {
    use PreprocessedHistoryFilterValue as Preprocessed;

    let resolved_filter = match value {
        HistoryFilterValue::CredentialId(id) => {
            let entity_ids = resolve_entity_ids(db, credential_id_related_subqueries(id)).await?;
            Preprocessed::EntityIds(entity_ids).condition()
                | (Preprocessed::EntityIds(vec![id.into()]).condition()
                    & Preprocessed::EntityTypes(vec![HistoryEntityType::Credential]))
                | (Preprocessed::Target(id.to_string()).condition()
                    & Preprocessed::EntityTypes(vec![HistoryEntityType::Notification]))
        }
        HistoryFilterValue::CredentialSchemaId(id) => {
            let entity_ids =
                resolve_entity_ids(db, credential_schema_id_related_subqueries(id)).await?;
            Preprocessed::EntityIds(entity_ids).condition()
                | (Preprocessed::EntityIds(vec![id.into()]).condition()
                    & Preprocessed::EntityTypes(vec![HistoryEntityType::CredentialSchema]))
        }
        HistoryFilterValue::ProofSchemaId(id) => {
            let entity_ids = resolve_entity_ids(db, proof_schema_id_related_subqueries(id)).await?;
            Preprocessed::EntityIds(entity_ids).condition()
                | (Preprocessed::EntityIds(vec![id.into()]).condition()
                    & Preprocessed::EntityTypes(vec![HistoryEntityType::ProofSchema]))
        }
        HistoryFilterValue::TrustCollectionId(id) => {
            let entity_ids =
                resolve_entity_ids(db, trust_collection_id_related_subqueries(id)).await?;
            Preprocessed::EntityIds(entity_ids).condition()
                | (Preprocessed::EntityIds(vec![id.into()]).condition()
                    & Preprocessed::EntityTypes(vec![HistoryEntityType::TrustCollection]))
        }
        HistoryFilterValue::SearchQuery(search_text, search_type) => {
            let entity_ids =
                resolve_entity_ids(db, search_query_subqueries(search_text, search_type)).await?;
            Preprocessed::EntityIds(entity_ids).condition()
        }
        // Pass-through variants that need no resolution — mapped explicitly so a newly added
        // variant forces a decision here rather than silently falling through.
        HistoryFilterValue::EntityTypes(v) => Preprocessed::EntityTypes(v).condition(),
        HistoryFilterValue::EntityIds(v) => Preprocessed::EntityIds(v).condition(),
        HistoryFilterValue::Actions(v) => Preprocessed::Actions(v).condition(),
        HistoryFilterValue::CreatedDate(v) => Preprocessed::CreatedDate(v).condition(),
        HistoryFilterValue::IdentifierId(v) => Preprocessed::IdentifierId(v).condition(),
        HistoryFilterValue::OrganisationIds(v) => Preprocessed::OrganisationIds(v).condition(),
        HistoryFilterValue::ProofId(v) => Preprocessed::ProofId(v).condition(),
        HistoryFilterValue::Users(v) => Preprocessed::Users(v).condition(),
        HistoryFilterValue::Sources(v) => Preprocessed::Sources(v).condition(),
    };
    Ok(resolved_filter)
}

/// Runs the subqueries (each selecting a single id column aliased to `entity_id`) concurrently and
/// returns the de-duplicated union of the resulting ids.
async fn resolve_entity_ids(
    db: &impl ConnectionTrait,
    subqueries: Vec<SelectStatement>,
) -> Result<Vec<EntityId>, DataLayerError> {
    let backend = db.get_database_backend();
    let rows_per_subquery = try_join_all(
        subqueries
            .iter()
            .map(|subquery| EntityIdRow::find_by_statement(backend.build(subquery)).all(db)),
    )
    .await
    .map_err(|err| DataLayerError::Db(err.into()))?;

    let entity_ids: HashSet<EntityId> = rows_per_subquery
        .into_iter()
        .flatten()
        .map(|row| row.entity_id)
        .collect();
    Ok(entity_ids.into_iter().collect())
}

pub(super) struct CountOperationsQuery(pub SelectStatement);
pub(super) fn count_ops_query(
    entity_type: history::HistoryEntityType,
    actions: &[history::HistoryAction],
    from_inclusive: Option<OffsetDateTime>,
    to_exclusive: OffsetDateTime,
    organisation_id: Option<OrganisationId>,
) -> CountOperationsQuery {
    let mut query = Query::select()
        .expr_as(Func::count(ColumnRef::Asterisk(None)), Alias::new("count"))
        .from(history::Entity)
        // the operations time cutoff is exclusive because the timelines query is inclusive
        .and_where(Expr::col((history::Entity, history::Column::CreatedDate)).lt(to_exclusive))
        .and_where(Expr::col(history::Column::EntityType).eq(entity_type))
        .and_where(Expr::col(history::Column::Action).is_in(actions))
        .to_owned();
    credential_proof_role_conditions(&mut query, entity_type);
    if let Some(from_inclusive) = from_inclusive {
        query.and_where(
            Expr::col((history::Entity, history::Column::CreatedDate)).gte(from_inclusive),
        );
    }
    if let Some(organisation_id) = organisation_id {
        query.and_where(Expr::col(history::Column::OrganisationId).eq(organisation_id));
    }
    CountOperationsQuery(query)
}

pub(super) fn org_timelines_query(
    from: Option<OffsetDateTime>,
    to: OffsetDateTime,
    organisation_id: OrganisationId,
    db_backend: SupportedDbType,
) -> Result<SelectStatement, DataLayerError> {
    let resolution = TimeResolution::new(from, to);
    let rounded_date = Alias::new("timestamp");
    let mut query = Query::select()
        .expr_as(Func::count(ColumnRef::Asterisk(None)), Alias::new("count"))
        .expr_as(
            resolution.floored_time_format_expr("history.created_date", db_backend)?,
            rounded_date.clone(),
        )
        .columns([history::Column::EntityType, history::Column::Action])
        .from(history::Entity)
        // Left join proofs and credentials to filter by ROLE
        .left_join(
            credential::Entity,
            Expr::col(history::Column::EntityId)
                .eq(Expr::col((credential::Entity, credential::Column::Id))),
        )
        .left_join(
            proof::Entity,
            Expr::col(history::Column::EntityId).eq(Expr::col((proof::Entity, proof::Column::Id))),
        )
        .to_owned();

    if let Some(from) = from {
        query
            // Align to bucket windows to selected resolution (lower inclusive, upper exclusive)
            // otherwise first and last bucket will have missing values.
            .and_where(
                Expr::col((history::Entity, history::Column::CreatedDate))
                    .gte(floor(from, resolution)?),
            );
    }

    query
        .and_where(
            Expr::col((history::Entity, history::Column::CreatedDate)).lt(ceil(to, resolution)?),
        )
        .and_where(Expr::col(history::Column::OrganisationId).eq(organisation_id))
        .and_where(
            Expr::col(history::Column::EntityType)
                .eq(history::HistoryEntityType::Credential)
                .and(Expr::col(history::Column::Action).is_in([
                    history::HistoryAction::Offered,
                    history::HistoryAction::Issued,
                    history::HistoryAction::Rejected,
                    history::HistoryAction::Suspended,
                    history::HistoryAction::Reactivated,
                    history::HistoryAction::Revoked,
                    history::HistoryAction::Errored,
                ]))
                .and(
                    Expr::col((credential::Entity, credential::Column::Role))
                        .eq(credential::CredentialRole::Issuer),
                )
                .or(Expr::col(history::Column::EntityType)
                    .eq(history::HistoryEntityType::Proof)
                    .and(Expr::col(history::Column::Action).is_in([
                        history::HistoryAction::Pending,
                        history::HistoryAction::Accepted,
                        history::HistoryAction::Rejected,
                        history::HistoryAction::Errored,
                    ]))
                    .and(
                        Expr::col((proof::Entity, proof::Column::Role))
                            .eq(proof::ProofRole::Verifier),
                    )),
        )
        .group_by_columns([
            rounded_date.clone().into_column_ref(),
            history::Column::EntityType.into_column_ref(),
            history::Column::Action.into_column_ref(),
        ])
        .order_by(rounded_date, Order::Asc);
    Ok(query)
}

pub(super) fn top_orgs_query(
    entity_type: history::HistoryEntityType,
    action: history::HistoryAction,
    from: Option<OffsetDateTime>,
    to: OffsetDateTime,
    num_orgs: usize,
) -> SelectStatement {
    let count = Alias::new("count");
    let mut query = Query::select()
        .expr_as(Func::count(ColumnRef::Asterisk(None)), count.clone())
        .columns([history::Column::OrganisationId])
        .from(history::Entity)
        .and_where(Expr::col(history::Column::EntityType).eq(entity_type))
        .and_where(Expr::col(history::Column::Action).eq(action))
        .to_owned();
    credential_proof_role_conditions(&mut query, entity_type);
    if let Some(from) = from {
        query.and_where(Expr::col((history::Entity, history::Column::CreatedDate)).gte(from));
    }
    query
        .and_where(Expr::col((history::Entity, history::Column::CreatedDate)).lt(to))
        .group_by_col(history::Column::OrganisationId)
        .order_by(count, Order::Desc)
        .limit(num_orgs as u64);
    query
}

fn credential_proof_role_conditions(
    query: &mut SelectStatement,
    entity_type: history::HistoryEntityType,
) {
    match entity_type {
        history::HistoryEntityType::Credential => {
            query
                .inner_join(
                    credential::Entity,
                    Expr::col(history::Column::EntityId)
                        .eq(Expr::col((credential::Entity, credential::Column::Id))),
                )
                .and_where(
                    Expr::col(credential::Column::Role).eq(credential::CredentialRole::Issuer),
                );
        }
        history::HistoryEntityType::Proof => {
            query
                .inner_join(
                    proof::Entity,
                    Expr::col(history::Column::EntityId)
                        .eq(Expr::col((proof::Entity, proof::Column::Id))),
                )
                .and_where(Expr::col(proof::Column::Role).eq(proof::ProofRole::Verifier));
        }
        _ => {
            // nothing to do
        }
    }
}

impl TimeResolution {
    fn floored_time_format_expr(
        &self,
        col: &str,
        db_backend: SupportedDbType,
    ) -> Result<SimpleExpr, DataLayerError> {
        let format = if db_backend == SupportedDbType::Postgres {
            match self {
                TimeResolution::Hour => "hour",
                TimeResolution::Day => "day",
                TimeResolution::Month => "month",
                TimeResolution::Year => "year",
            }
        } else {
            match self {
                TimeResolution::Hour => "%Y-%m-%dT%H:00:00Z",
                TimeResolution::Day => "%Y-%m-%dT00:00:00Z",
                TimeResolution::Month => "%Y-%m-01T00:00:00Z",
                TimeResolution::Year => "%Y-01-01T00:00:00Z",
            }
        };
        let expr = match db_backend {
            SupportedDbType::MySql => Expr::cust(format!(
                "STR_TO_DATE(DATE_FORMAT({col}, '{format}'), '%Y-%m-%dT%H:%i:%sZ')"
            )),
            SupportedDbType::Sqlite => Expr::cust(format!("strftime('{format}', {col})")),
            SupportedDbType::Postgres => Expr::cust(format!("date_trunc('{format}', {col})")),
        };
        Ok(expr)
    }
}

impl IntoFilterCondition for StatsBySchemaFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::From(date) => get_comparison_condition(history::Column::CreatedDate, date),
            Self::To(date) => get_comparison_condition(history::Column::CreatedDate, date),
            Self::OrganisationId(organisation_id) => history::Column::OrganisationId
                .eq(organisation_id)
                .into_condition(),
        }
    }
}

impl IntoFilterCondition for SystemStatsFilterValue {
    fn get_condition(self, _entire_filter: &ListFilterCondition<Self>) -> Condition {
        match self {
            Self::From(date) => get_comparison_condition(history::Column::CreatedDate, date),
            Self::To(date) => get_comparison_condition(history::Column::CreatedDate, date),
        }
    }
}

impl IntoSortingColumn for SortableIssuerStatisticsColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Issued => (
                Alias::new(history::HistoryAction::Issued.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Revoked => (
                Alias::new(history::HistoryAction::Revoked.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Suspended => (
                Alias::new(history::HistoryAction::Suspended.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Reactivated => (
                Alias::new(history::HistoryAction::Reactivated.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Error => (
                Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
                Default::default(),
            ),
        }
    }
}

impl IntoSortingColumn for SortableVerifierStatisticsColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Accepted => (
                Alias::new(history::HistoryAction::Accepted.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Rejected => (
                Alias::new(history::HistoryAction::Rejected.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Error => (
                Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
                Default::default(),
            ),
        }
    }
}

const CLO_COLUMN: &str = "credential_lifecycle_operation";

impl IntoSortingColumn for SortableSystemInteractionStatisticsColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::Issued => (
                Alias::new(history::HistoryAction::Issued.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Verified => (
                Alias::new(history::HistoryAction::Accepted.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::CredentialLifecycleOperation => {
                (Alias::new(CLO_COLUMN).into_column_ref(), Default::default())
            }
            Self::Error => (
                Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
                Default::default(),
            ),
        }
    }
}

impl IntoSortingColumn for SortableSystemManagementStatisticsColumn {
    fn get_column(&self) -> (ColumnRef, ColumnSortingBehavior) {
        match self {
            Self::CredentialSchema => (
                Alias::new(history::HistoryEntityType::CredentialSchema.to_value())
                    .into_column_ref(),
                Default::default(),
            ),
            Self::ProofSchema => (
                Alias::new(history::HistoryEntityType::ProofSchema.to_value()).into_column_ref(),
                Default::default(),
            ),
            Self::Identifier => (
                Alias::new(history::HistoryEntityType::Identifier.to_value()).into_column_ref(),
                Default::default(),
            ),
        }
    }
}

const ISSUER_ACTIONS: [history::HistoryAction; 5] = [
    history::HistoryAction::Issued,
    history::HistoryAction::Suspended,
    history::HistoryAction::Reactivated,
    history::HistoryAction::Revoked,
    history::HistoryAction::Errored,
];
pub(super) fn issuer_stats_query(
    query: &IssuerStatsQuery,
    db_backend: SupportedDbType,
) -> SelectStatement {
    let mut stmt = history::Entity::find()
        .with_list_query(query, db_backend)
        .into_query();
    let group_columns = [
        history::Column::Name.into_column_ref(),
        credential::Column::CredentialSchemaId.into_column_ref(),
    ];
    stmt.clear_selects()
        .columns(group_columns.clone())
        .group_by_columns(group_columns)
        .inner_join(
            credential::Entity,
            Expr::col(history::Column::EntityId)
                .eq(Expr::col((credential::Entity, credential::Column::Id))),
        )
        // Only issuer actions are relevant
        .and_where(credential::Column::Role.eq(credential::CredentialRole::Issuer))
        .and_where(history::Column::Action.is_in(ISSUER_ACTIONS));

    for action in ISSUER_ACTIONS {
        stmt.expr_as(
            // Each history event is counted once (the other cases are `null`, which do _not_ count)
            Func::count(CaseStatement::new().case(history::Column::Action.eq(action), 1)),
            Alias::new(action.to_value()),
        );
    }
    stmt
}

const VERIFIER_ACTIONS: [history::HistoryAction; 3] = [
    history::HistoryAction::Accepted,
    history::HistoryAction::Rejected,
    history::HistoryAction::Errored,
];
pub(super) fn verifier_stats_query(
    query: &VerifierStatsQuery,
    db_backend: SupportedDbType,
) -> SelectStatement {
    let mut stmt = history::Entity::find()
        .with_list_query(query, db_backend)
        .into_query();
    let group_columns = [
        history::Column::Name.into_column_ref(),
        proof::Column::ProofSchemaId.into_column_ref(),
    ];
    stmt.clear_selects()
        .columns(group_columns.clone())
        .group_by_columns(group_columns)
        .inner_join(
            proof::Entity,
            Expr::col(history::Column::EntityId).eq(Expr::col((proof::Entity, proof::Column::Id))),
        )
        // Only verifier actions are relevant
        .and_where(proof::Column::Role.eq(proof::ProofRole::Verifier))
        .and_where(history::Column::Action.is_in(VERIFIER_ACTIONS));

    for action in VERIFIER_ACTIONS {
        stmt.expr_as(
            // Each history event is counted once (the other cases are `null`, which do _not_ count)
            Func::count(CaseStatement::new().case(history::Column::Action.eq(action), 1)),
            Alias::new(action.to_value()),
        );
    }
    stmt
}

pub(super) fn system_interaction_stats_query(
    query: &SystemInteractionStatsQuery,
    db_backend: SupportedDbType,
) -> SelectStatement {
    let mut stmt = history::Entity::find()
        .with_list_query(query, db_backend)
        .into_query();
    stmt.clear_selects()
        .column(history::Column::OrganisationId)
        .group_by_col(history::Column::OrganisationId)
        .left_join(
            credential::Entity,
            Expr::col(history::Column::EntityId)
                .eq(Expr::col((credential::Entity, credential::Column::Id))),
        )
        .left_join(
            proof::Entity,
            Expr::col(history::Column::EntityId).eq(Expr::col((proof::Entity, proof::Column::Id))),
        )
        .and_where(
            Expr::col(history::Column::EntityType)
                .eq(history::HistoryEntityType::Credential)
                .and(Expr::col(history::Column::Action).is_in([
                    history::HistoryAction::Issued,
                    history::HistoryAction::Suspended,
                    history::HistoryAction::Reactivated,
                    history::HistoryAction::Revoked,
                    history::HistoryAction::Errored,
                ]))
                .and(
                    Expr::col((credential::Entity, credential::Column::Role))
                        .eq(credential::CredentialRole::Issuer),
                )
                .or(Expr::col(history::Column::EntityType)
                    .eq(history::HistoryEntityType::Proof)
                    .and(Expr::col(history::Column::Action).is_in([
                        history::HistoryAction::Accepted,
                        history::HistoryAction::Errored,
                    ]))
                    .and(
                        Expr::col((proof::Entity, proof::Column::Role))
                            .eq(proof::ProofRole::Verifier),
                    )),
        );
    for action in [
        history::HistoryAction::Issued,
        history::HistoryAction::Accepted,
        history::HistoryAction::Errored,
    ] {
        stmt.expr_as(
            // Each history event is counted once (the other cases are `null`, which do _not_ count)
            Func::count(CaseStatement::new().case(history::Column::Action.eq(action), 1)),
            Alias::new(action.to_value()),
        );
    }
    stmt.expr_as(
        // Each history event is counted once (the other cases are `null`, which do _not_ count)
        Func::count(CaseStatement::new().case(
            history::Column::Action.is_in([
                history::HistoryAction::Suspended,
                history::HistoryAction::Reactivated,
                history::HistoryAction::Revoked,
            ]),
            1,
        )),
        Alias::new(CLO_COLUMN),
    );
    stmt
}

pub(super) fn system_management_stats_query(
    query: &SystemManagementStatsQuery,
    db_backend: SupportedDbType,
) -> SelectStatement {
    let mut stmt = history::Entity::find()
        .with_list_query(query, db_backend)
        .into_query();
    stmt.clear_selects()
        .column((history::Entity, history::Column::OrganisationId))
        .group_by_col((history::Entity, history::Column::OrganisationId))
        .left_join(
            identifier::Entity,
            Expr::col(history::Column::EntityId)
                .eq(Expr::col((identifier::Entity, identifier::Column::Id))),
        )
        .and_where(
            Expr::col(history::Column::EntityType)
                .eq(history::HistoryEntityType::Identifier)
                .and(Expr::col(history::Column::Action).eq(history::HistoryAction::Created))
                .and(Expr::col((identifier::Entity, identifier::Column::IsRemote)).eq(false))
                .or(Expr::col(history::Column::EntityType)
                    .is_in([
                        history::HistoryEntityType::CredentialSchema,
                        history::HistoryEntityType::ProofSchema,
                    ])
                    .and(Expr::col(history::Column::Action).eq(history::HistoryAction::Created))),
        );
    for entity_type in [
        history::HistoryEntityType::CredentialSchema,
        history::HistoryEntityType::ProofSchema,
        history::HistoryEntityType::Identifier,
    ] {
        stmt.expr_as(
            // Each history event is counted once (the other cases are `null`, which do _not_ count)
            Func::count(CaseStatement::new().case(history::Column::EntityType.eq(entity_type), 1)),
            Alias::new(entity_type.to_value()),
        );
    }
    stmt
}
