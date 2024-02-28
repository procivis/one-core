use sea_orm::{
    sea_query::{
        ColumnRef, Condition, Expr, IntoCondition, IntoIden, IntoTableRef, Query, SimpleExpr,
    },
    ColumnTrait, IntoSimpleExpr, JoinType, RelationTrait,
};

use crate::{
    entity::{
        claim, claim_schema, credential, credential_schema, did, history, proof, proof_claim,
        proof_schema_claim_schema,
    },
    list_query_generic::{
        get_equals_condition, get_greater_than_condition, get_lesser_than_condition,
        IntoFilterCondition, IntoJoinCondition, IntoSortingColumn, JoinRelation,
    },
};
use one_core::model::history::{HistoryFilterValue, HistorySearchEnum, SortableHistoryColumn};

impl IntoSortingColumn for SortableHistoryColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            SortableHistoryColumn::CreatedDate => history::Column::CreatedDate,
            SortableHistoryColumn::Action => history::Column::Action,
            SortableHistoryColumn::EntityType => history::Column::EntityType,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for HistoryFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            HistoryFilterValue::EntityTypes(entity_types) => history::Column::EntityType
                .is_in(
                    entity_types
                        .into_iter()
                        .map(history::HistoryEntityType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            HistoryFilterValue::EntityId(entity_id) => {
                get_equals_condition(history::Column::EntityId, entity_id)
            }
            HistoryFilterValue::Action(action) => get_equals_condition(
                history::Column::Action,
                history::HistoryAction::from(action),
            ),
            HistoryFilterValue::CreatedDateFrom(created_date_from) => {
                get_greater_than_condition(history::Column::CreatedDate, created_date_from)
            }
            HistoryFilterValue::CreatedDateTo(created_date_to) => {
                get_lesser_than_condition(history::Column::CreatedDate, created_date_to)
            }
            HistoryFilterValue::DidId(did_id) => credential::Column::IssuerDidId
                .eq(did_id)
                .or(credential::Column::HolderDidId.eq(did_id))
                .or(proof::Column::VerifierDidId.eq(did_id))
                .or(history::Column::EntityId
                    .eq(did_id)
                    .and(history::Column::EntityType.eq(history::HistoryEntityType::Did)))
                .into_condition(),
            HistoryFilterValue::CredentialId(credential_id) => history::Column::EntityId
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
                .into_condition(),
            HistoryFilterValue::CredentialSchemaId(credential_schema_id) => {
                credential_schema_filter_condition(
                    history::Column::EntityId.eq(credential_schema_id.to_string()),
                    credential_schema::Column::Id.eq(credential_schema_id.to_string()),
                )
            }
            HistoryFilterValue::SearchQuery(search_text, search_type) => {
                search_query_filter(search_text, search_type)
            }
            HistoryFilterValue::OrganisationId(organisation_id) => {
                get_equals_condition(history::Column::OrganisationId, organisation_id.to_string())
            }
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
                        proof_schema_claim_schema::Entity,
                        Expr::col((claim::Entity, claim::Column::ClaimSchemaId)).eq(Expr::col((
                            proof_schema_claim_schema::Entity,
                            proof_schema_claim_schema::Column::ClaimSchemaId,
                        ))),
                    )
                    .inner_join(
                        proof::Entity,
                        Expr::col((
                            proof_schema_claim_schema::Entity,
                            proof_schema_claim_schema::Column::ProofSchemaId,
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
                        proof_schema_claim_schema::Entity,
                        Expr::col((claim::Entity, claim::Column::ClaimSchemaId)).eq(Expr::col((
                            proof_schema_claim_schema::Entity,
                            proof_schema_claim_schema::Column::ClaimSchemaId,
                        ))),
                    )
                    .inner_join(
                        proof::Entity,
                        Expr::col((
                            proof_schema_claim_schema::Entity,
                            proof_schema_claim_schema::Column::ProofSchemaId,
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
        HistorySearchEnum::IssuerDid => search_query_did_filter_condition(
            credential::Column::Id,
            credential::Column::IssuerDidId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::IssuerName => search_query_did_filter_condition(
            credential::Column::Id,
            credential::Column::IssuerDidId,
            did::Column::Name.contains(search_text),
        ),
        HistorySearchEnum::VerifierDid => search_query_did_filter_condition(
            proof::Column::Id,
            proof::Column::VerifierDidId,
            did::Column::Did.contains(search_text),
        ),
        HistorySearchEnum::VerifierName => search_query_did_filter_condition(
            proof::Column::Id,
            proof::Column::VerifierDidId,
            did::Column::Name.contains(search_text),
        ),
    }
}

fn search_query_did_filter_condition(
    id_column: impl ColumnTrait,
    did_id_column: impl ColumnTrait + IntoIden,
    condition: impl IntoCondition + Clone,
) -> Condition {
    history::Column::EntityId
        .in_subquery(
            Query::select()
                .expr(id_column.into_expr())
                .from(id_column.entity_name().into_table_ref())
                .inner_join(
                    did::Entity,
                    Expr::col(ColumnRef::TableColumn(
                        did_id_column.entity_name(),
                        did_id_column.into_iden(),
                    ))
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
                    did_id_column.entity_name(),
                    Expr::col(ColumnRef::TableColumn(
                        did_id_column.entity_name(),
                        did_id_column.into_iden(),
                    ))
                    .eq(Expr::col((did::Entity, did::Column::Id))),
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

impl IntoJoinCondition for HistoryFilterValue {
    fn get_join(self) -> Vec<JoinRelation> {
        match self {
            HistoryFilterValue::DidId(_) => {
                vec![
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: history::Relation::MentionedCredential.def(),
                    },
                    JoinRelation {
                        join_type: JoinType::LeftJoin,
                        relation_def: history::Relation::MentionedProof.def(),
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
