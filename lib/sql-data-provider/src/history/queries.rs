use one_core::model::history::{
    HistoryFilterValue, HistorySearchEnum, IssuerStatsQuery, SortableHistoryColumn,
    SortableIssuerStatisticsColumn, SortableSystemInteractionStatisticsColumn,
    SortableSystemManagementStatisticsColumn, SortableVerifierStatisticsColumn,
    StatsBySchemaFilterValue, SystemInteractionStatsQuery, SystemManagementStatsQuery,
    SystemStatsFilterValue, VerifierStatsQuery,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::repository::error::DataLayerError;
use one_dto_mapper::convert_inner;
use sea_orm::sea_query::{
    Alias, CaseStatement, ColumnRef, Condition, Expr, Func, IntoColumnRef, IntoCondition, IntoIden,
    IntoTableRef, Query, SelectStatement, SimpleExpr,
};
use sea_orm::{
    ActiveEnum, ColumnTrait, DbBackend, EntityTrait, IntoSimpleExpr, JoinType, Order, QueryFilter,
    QuerySelect, QueryTrait, RelationTrait,
};
use shared_types::OrganisationId;
use time::OffsetDateTime;

use crate::entity::{
    claim, claim_schema, credential, credential_schema, did, history, identifier, proof,
    proof_claim, proof_input_claim_schema, proof_input_schema, proof_schema,
};
use crate::history::mapper::{ceil, floor};
use crate::history::model::TimeResolution;
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation, SelectWithListQuery,
    get_comparison_condition,
};

impl IntoSortingColumn for SortableHistoryColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => history::Column::CreatedDate,
            Self::Action => history::Column::Action,
            Self::EntityType => history::Column::EntityType,
            Self::Source => history::Column::Source,
            Self::User => history::Column::User,
            Self::OrganisationId => history::Column::OrganisationId,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for HistoryFilterValue {
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
            Self::CredentialId(credential_id) => history::Column::EntityId
                .eq(credential_id)
                .and(history::Column::EntityType.eq(history::HistoryEntityType::Credential))
                .or(history::Column::EntityId.in_subquery(
                    Query::select()
                        .expr(proof_claim::Column::ProofId.into_expr())
                        .from(proof_claim::Entity)
                        .inner_join(
                            claim::Entity,
                            Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                                .eq(Expr::col((claim::Entity, claim::Column::Id))),
                        )
                        .cond_where(claim::Column::CredentialId.eq(credential_id))
                        .to_owned(),
                ))
                .or(history::Column::Target
                    .eq(credential_id)
                    .and(history::Column::EntityType.eq(history::HistoryEntityType::Notification)))
                .into_condition(),
            Self::CredentialSchemaId(credential_schema_id) => credential_schema_filter_condition(
                history::Column::EntityId.eq(credential_schema_id.to_string()),
                credential_schema::Column::Id.eq(credential_schema_id.to_string()),
            ),
            Self::SearchQuery(search_text, search_type) => {
                search_query_filter(search_text, search_type)
            }
            Self::OrganisationIds(organisation_ids) => history::Column::OrganisationId
                .is_in(organisation_ids)
                .into_condition(),
            Self::ProofSchemaId(proof_schema_id) => history::Column::EntityId
                .eq(proof_schema_id)
                .and(history::Column::EntityType.eq(history::HistoryEntityType::ProofSchema))
                .or(history::Column::EntityId.in_subquery(
                    Query::select()
                        .expr(proof::Column::Id.into_expr())
                        .from(proof::Entity)
                        .inner_join(
                            proof_schema::Entity,
                            Expr::col((proof_schema::Entity, proof_schema::Column::Id))
                                .eq(Expr::col((proof::Entity, proof::Column::ProofSchemaId))),
                        )
                        .cond_where(proof_schema::Column::Id.eq(proof_schema_id.to_string()))
                        .to_owned(),
                ))
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
        }
    }
}

fn search_query_filter(search_text: String, search_type: HistorySearchEnum) -> Condition {
    match search_type {
        HistorySearchEnum::All => search_all_condition(search_text),
        HistorySearchEnum::ClaimName => history::Column::EntityId
            .in_subquery(
                Query::select()
                    .expr(claim::Column::CredentialId.into_expr())
                    .from(claim::Entity)
                    .inner_join(
                        claim_schema::Entity,
                        Expr::col((claim_schema::Entity, claim_schema::Column::Id))
                            .eq(Expr::col((claim::Entity, claim::Column::ClaimSchemaId))),
                    )
                    .cond_where(claim_schema::Column::Key.contains(search_text.to_owned()))
                    .to_owned(),
            )
            .or(history::Column::EntityId.in_subquery(
                Query::select()
                    .expr(proof::Column::Id.into_expr())
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
            ))
            .into_condition(),
        HistorySearchEnum::ClaimValue => history::Column::EntityId
            .in_subquery(
                Query::select()
                    .expr(claim::Column::CredentialId.into_expr())
                    .from(claim::Entity)
                    .cond_where(claim::Column::Value.contains(search_text.to_owned()))
                    .to_owned(),
            )
            .or(history::Column::EntityId.in_subquery(
                Query::select()
                    .expr(proof::Column::Id.into_expr())
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
                    .cond_where(claim::Column::Value.contains(search_text))
                    .to_owned(),
            ))
            .into_condition(),
        HistorySearchEnum::CredentialSchemaName => credential_schema_name_search_condition(
            credential_schema::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::IssuerDid => search_query_identifier_filter_condition(
            credential::Column::Id,
            credential::Column::IssuerIdentifierId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::IssuerName => search_query_identifier_filter_condition(
            credential::Column::Id,
            credential::Column::IssuerIdentifierId,
            did::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::VerifierDid => search_query_identifier_filter_condition(
            proof::Column::Id,
            proof::Column::VerifierIdentifierId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::VerifierName => search_query_identifier_filter_condition(
            proof::Column::Id,
            proof::Column::VerifierIdentifierId,
            did::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::ProofSchemaName => history::Column::EntityId
            .in_subquery(
                proof_schema::Entity::find()
                    .filter(proof_schema::Column::Name.contains(search_text))
                    .select_only()
                    .column(proof_schema::Column::Id)
                    .into_query(),
            )
            .into_condition(),
    }
}

fn search_query_identifier_filter_condition(
    entity_id_column: impl ColumnTrait,
    identifier_id_column: impl ColumnTrait + IntoIden,
    condition: impl IntoCondition + Clone,
) -> Condition {
    history::Column::EntityId
        .in_subquery(
            Query::select()
                .expr(entity_id_column.into_expr())
                .from(entity_id_column.entity_name().into_table_ref())
                .inner_join(
                    identifier::Entity,
                    Expr::col(ColumnRef::TableColumn(
                        identifier_id_column.entity_name(),
                        identifier_id_column.into_iden(),
                    ))
                    .eq(Expr::col((identifier::Entity, identifier::Column::Id))),
                )
                .inner_join(
                    did::Entity,
                    Expr::col((identifier::Entity, identifier::Column::DidId))
                        .eq(Expr::col((did::Entity, did::Column::Id))),
                )
                .cond_where(condition.to_owned())
                .to_owned(),
        )
        .or(history::Column::EntityId.in_subquery(
            Query::select()
                .expr(did::Column::Id.into_expr())
                .from(did::Entity)
                .inner_join(
                    identifier::Entity,
                    Expr::col((did::Entity, did::Column::Id))
                        .eq(Expr::col((identifier::Entity, identifier::Column::DidId))),
                )
                .inner_join(
                    identifier_id_column.entity_name(),
                    Expr::col(ColumnRef::TableColumn(
                        identifier_id_column.entity_name(),
                        identifier_id_column.into_iden(),
                    ))
                    .eq(Expr::col((identifier::Entity, identifier::Column::Id))),
                )
                .cond_where(condition)
                .to_owned(),
        ))
        .into_condition()
}

fn credential_schema_name_search_condition(
    credential_schema_match_condition: SimpleExpr,
) -> Condition {
    history::Column::EntityId
        .in_subquery(
            Query::select()
                .expr(proof_claim::Column::ProofId.into_expr())
                .from(proof_claim::Entity)
                .inner_join(
                    claim::Entity,
                    Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                        .eq(Expr::col((claim::Entity, claim::Column::Id))),
                )
                .inner_join(
                    credential::Entity,
                    Expr::col((claim::Entity, claim::Column::CredentialId))
                        .eq(Expr::col((credential::Entity, credential::Column::Id))),
                )
                .inner_join(
                    credential_schema::Entity,
                    Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(
                        Expr::col((credential_schema::Entity, credential_schema::Column::Id)),
                    ),
                )
                .cond_where(credential_schema_match_condition.to_owned())
                .to_owned(),
        )
        .or(history::Column::EntityId.in_subquery(
            Query::select()
                .expr(credential::Column::Id.into_expr())
                .from(credential::Entity)
                .inner_join(
                    credential_schema::Entity,
                    Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(
                        Expr::col((credential_schema::Entity, credential_schema::Column::Id)),
                    ),
                )
                .cond_where(credential_schema_match_condition.to_owned())
                .to_owned(),
        ))
        .or(history::Column::EntityId.in_subquery(
            Query::select()
                .expr(credential_schema::Column::Id.into_expr())
                .from(credential_schema::Entity)
                .cond_where(credential_schema_match_condition)
                .to_owned(),
        ))
        .into_condition()
}

fn credential_schema_filter_condition(
    starting_expression: SimpleExpr,
    credential_schema_match_condition: SimpleExpr,
) -> Condition {
    starting_expression
        .and(history::Column::EntityType.eq(history::HistoryEntityType::CredentialSchema))
        .or(history::Column::EntityId.in_subquery(
            Query::select()
                .expr(proof_claim::Column::ProofId.into_expr())
                .from(proof_claim::Entity)
                .inner_join(
                    claim::Entity,
                    Expr::col((proof_claim::Entity, proof_claim::Column::ClaimId))
                        .eq(Expr::col((claim::Entity, claim::Column::Id))),
                )
                .inner_join(
                    credential::Entity,
                    Expr::col((claim::Entity, claim::Column::CredentialId))
                        .eq(Expr::col((credential::Entity, credential::Column::Id))),
                )
                .inner_join(
                    credential_schema::Entity,
                    Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(
                        Expr::col((credential_schema::Entity, credential_schema::Column::Id)),
                    ),
                )
                .cond_where(credential_schema_match_condition.to_owned())
                .to_owned(),
        ))
        .or(history::Column::EntityId.in_subquery(
            Query::select()
                .expr(credential::Column::Id.into_expr())
                .from(credential::Entity)
                .inner_join(
                    credential_schema::Entity,
                    Expr::col((credential::Entity, credential::Column::CredentialSchemaId)).eq(
                        Expr::col((credential_schema::Entity, credential_schema::Column::Id)),
                    ),
                )
                .cond_where(credential_schema_match_condition)
                .to_owned(),
        ))
        .into_condition()
}

impl IntoJoinRelations for HistoryFilterValue {
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

fn search_all_condition(search_text: String) -> Condition {
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
    .fold(Condition::any(), |cond, entry| {
        cond.add(search_query_filter(search_text.to_owned(), entry))
    })
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
        .expr_as(Func::count(ColumnRef::Asterisk), Alias::new("count"))
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
    db_backend: &DbBackend,
) -> Result<SelectStatement, DataLayerError> {
    let resolution = TimeResolution::new(from, to);
    let rounded_date = Alias::new("timestamp");
    let mut query = Query::select()
        .expr_as(Func::count(ColumnRef::Asterisk), Alias::new("count"))
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
        .expr_as(Func::count(ColumnRef::Asterisk), count.clone())
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
        db_backend: &DbBackend,
    ) -> Result<SimpleExpr, DataLayerError> {
        let format = match self {
            TimeResolution::Hour => "%Y-%m-%dT%H:00:00Z",
            TimeResolution::Day => "%Y-%m-%dT00:00:00Z",
            TimeResolution::Month => "%Y-%m-01T00:00:00Z",
            TimeResolution::Year => "%Y-01-01T00:00:00Z",
        };
        let expr = match db_backend {
            DbBackend::MySql => Expr::cust(format!(
                "STR_TO_DATE(DATE_FORMAT({col}, '{format}'), '%Y-%m-%dT%H:%i:%sZ')"
            )),
            DbBackend::Sqlite => Expr::cust(format!("strftime('{format}', {col})")),
            DbBackend::Postgres => return Err(DataLayerError::UnsupportedDbBackend),
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
    fn get_column(&self) -> SimpleExpr {
        let col = match self {
            Self::Issued => Alias::new(history::HistoryAction::Issued.to_value()).into_column_ref(),
            Self::Revoked => {
                Alias::new(history::HistoryAction::Revoked.to_value()).into_column_ref()
            }
            Self::Suspended => {
                Alias::new(history::HistoryAction::Suspended.to_value()).into_column_ref()
            }
            Self::Reactivated => {
                Alias::new(history::HistoryAction::Reactivated.to_value()).into_column_ref()
            }
            Self::Error => Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
        };
        SimpleExpr::Column(col)
    }
}

impl IntoSortingColumn for SortableVerifierStatisticsColumn {
    fn get_column(&self) -> SimpleExpr {
        let col = match self {
            Self::Accepted => {
                Alias::new(history::HistoryAction::Accepted.to_value()).into_column_ref()
            }
            Self::Rejected => {
                Alias::new(history::HistoryAction::Rejected.to_value()).into_column_ref()
            }
            Self::Error => Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
        };
        SimpleExpr::Column(col)
    }
}

const CLO_COLUMN: &str = "credential_lifecycle_operation";

impl IntoSortingColumn for SortableSystemInteractionStatisticsColumn {
    fn get_column(&self) -> SimpleExpr {
        let col = match self {
            Self::Issued => Alias::new(history::HistoryAction::Issued.to_value()).into_column_ref(),
            Self::Verified => {
                Alias::new(history::HistoryAction::Accepted.to_value()).into_column_ref()
            }
            Self::CredentialLifecycleOperation => Alias::new(CLO_COLUMN).into_column_ref(),
            Self::Error => Alias::new(history::HistoryAction::Errored.to_value()).into_column_ref(),
        };
        SimpleExpr::Column(col)
    }
}

impl IntoSortingColumn for SortableSystemManagementStatisticsColumn {
    fn get_column(&self) -> SimpleExpr {
        let col = match self {
            Self::CredentialSchema => {
                Alias::new(history::HistoryEntityType::CredentialSchema.to_value())
                    .into_column_ref()
            }
            Self::ProofSchema => {
                Alias::new(history::HistoryEntityType::ProofSchema.to_value()).into_column_ref()
            }
            Self::Identifier => {
                Alias::new(history::HistoryEntityType::Identifier.to_value()).into_column_ref()
            }
        };
        SimpleExpr::Column(col)
    }
}

const ISSUER_ACTIONS: [history::HistoryAction; 5] = [
    history::HistoryAction::Issued,
    history::HistoryAction::Suspended,
    history::HistoryAction::Reactivated,
    history::HistoryAction::Revoked,
    history::HistoryAction::Errored,
];
pub(super) fn issuer_stats_query(query: &IssuerStatsQuery) -> SelectStatement {
    let mut stmt = history::Entity::find().with_list_query(query).into_query();
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
pub(super) fn verifier_stats_query(query: &VerifierStatsQuery) -> SelectStatement {
    let mut stmt = history::Entity::find().with_list_query(query).into_query();
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
) -> SelectStatement {
    let mut stmt = history::Entity::find().with_list_query(query).into_query();
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

pub(super) fn system_management_stats_query(query: &SystemManagementStatsQuery) -> SelectStatement {
    let mut stmt = history::Entity::find().with_list_query(query).into_query();
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
