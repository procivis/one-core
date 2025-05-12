use one_core::model::history::{HistoryFilterValue, HistorySearchEnum, SortableHistoryColumn};
use sea_orm::sea_query::{
    ColumnRef, Condition, Expr, IntoCondition, IntoIden, IntoTableRef, Query, SimpleExpr,
};
use sea_orm::{
    ColumnTrait, EntityTrait, IntoSimpleExpr, JoinType, QueryFilter, QuerySelect, QueryTrait,
    RelationTrait,
};

use crate::entity::{
    claim, claim_schema, credential, credential_schema, did, history, identifier, proof,
    proof_claim, proof_input_claim_schema, proof_input_schema, proof_schema,
};
use crate::list_query_generic::{
    IntoFilterCondition, IntoJoinRelations, IntoSortingColumn, JoinRelation,
    get_comparison_condition, get_equals_condition,
};

impl IntoSortingColumn for SortableHistoryColumn {
    fn get_column(&self) -> SimpleExpr {
        match self {
            Self::CreatedDate => history::Column::CreatedDate,
            Self::Action => history::Column::Action,
            Self::EntityType => history::Column::EntityType,
        }
        .into_simple_expr()
    }
}

impl IntoFilterCondition for HistoryFilterValue {
    fn get_condition(self) -> sea_orm::Condition {
        match self {
            Self::EntityTypes(entity_types) => history::Column::EntityType
                .is_in(
                    entity_types
                        .into_iter()
                        .map(history::HistoryEntityType::from)
                        .collect::<Vec<_>>(),
                )
                .into_condition(),
            Self::EntityId(entity_id) => get_equals_condition(history::Column::EntityId, entity_id),
            Self::EntityIds(entity_ids) => {
                history::Column::EntityId.is_in(entity_ids).into_condition()
            }
            Self::Action(action) => get_equals_condition(
                history::Column::Action,
                history::HistoryAction::from(action),
            ),
            Self::CreatedDate(date_comparison) => {
                get_comparison_condition(history::Column::CreatedDate, date_comparison)
            }
            Self::IdentifierId(identifier_id) => credential::Column::IssuerIdentifierId
                .eq(identifier_id)
                .or(credential::Column::HolderIdentifierId.eq(identifier_id))
                .or(proof::Column::VerifierIdentifierId.eq(identifier_id))
                .or(proof::Column::HolderIdentifierId.eq(identifier_id))
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
                .into_condition(),
            Self::CredentialSchemaId(credential_schema_id) => credential_schema_filter_condition(
                history::Column::EntityId.eq(credential_schema_id.to_string()),
                credential_schema::Column::Id.eq(credential_schema_id.to_string()),
            ),
            Self::SearchQuery(search_text, search_type) => {
                search_query_filter(search_text, search_type)
            }
            Self::OrganisationId(organisation_id) => {
                get_equals_condition(history::Column::OrganisationId, organisation_id.to_string())
            }
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
