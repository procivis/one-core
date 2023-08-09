use migration::{Alias, Query};
use sea_orm::sea_query::{expr::Expr, IntoCondition, SimpleExpr};
use sea_orm::{
    ColumnTrait, Condition, EntityTrait, IntoSimpleExpr, LoaderTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, RelationTrait, Select,
};

use crate::data_layer::data_model::ProofsDetailResponse;

use super::common::calculate_pages_count;
use super::data_model::{
    GetListQueryParams, GetProofsResponse, ProofsCombined, SortableProofColumn,
};
use super::entities::{did, proof, proof_schema, proof_state, Proof, ProofState};
use super::list_query::{GetEntityColumn, SelectWithListQuery};
use super::{DataLayer, DataLayerError};

impl GetEntityColumn for SortableProofColumn {
    fn get_simple_expr(&self) -> SimpleExpr {
        match self {
            SortableProofColumn::CreatedDate => proof::Column::CreatedDate.into_simple_expr(),
            SortableProofColumn::ProofSchemaName => proof_schema::Column::Name.into_simple_expr(),
            SortableProofColumn::VerifierDid => did::Column::Did.into_simple_expr(),
            SortableProofColumn::State => proof_state::Column::State.into_simple_expr(),
        }
    }
}

pub type GetProofsQuery = GetListQueryParams<SortableProofColumn>;

fn get_select_proofs_query(
    base_query: Select<Proof>,
    organisation_id: Option<String>,
) -> Select<Proof> {
    base_query
        .select_only()
        .columns([
            proof::Column::Id,
            proof::Column::IssuanceDate,
            proof::Column::CreatedDate,
            proof::Column::LastModified,
        ])
        .column_as(did::Column::Did, "verifier_did")
        .column(proof_state::Column::State)
        .column_as(proof::Column::Id.count(), "count")
        .column_as(proof_schema::Column::Id, "schema_id")
        .column_as(proof_schema::Column::Name, "schema_name")
        .column_as(proof_schema::Column::CreatedDate, "schema_created_date")
        .column_as(proof_schema::Column::LastModified, "schema_last_modified")
        .column_as(proof_schema::Column::OrganisationId, "organisation_id")
        // add related issuerDid
        .join_rev(
            sea_orm::JoinType::LeftJoin,
            proof::Relation::VerifierDid.def().rev(),
        )
        // add related schema
        .join_rev(
            sea_orm::JoinType::InnerJoin,
            proof::Relation::ProofSchema
                .def()
                .rev()
                .on_condition(move |_left, _right| match &organisation_id {
                    None => Condition::all(),
                    Some(id) => proof_schema::Column::OrganisationId.eq(id).into_condition(),
                }),
        )
        .group_by(proof::Column::Id)
        .join(
            sea_orm::JoinType::InnerJoin,
            proof::Relation::ProofState.def(),
        )
        // find most recent state
        .filter(
            proof_state::Column::CreatedDate
                .in_subquery(
                    Query::select()
                        .expr(
                            Expr::col((
                                Alias::new("inner_state"),
                                proof_state::Column::CreatedDate,
                            ))
                            .max(),
                        )
                        .from_as(proof_state::Entity, Alias::new("inner_state"))
                        .cond_where(
                            Expr::col((Alias::new("inner_state"), proof_state::Column::ProofId))
                                .equals((proof_state::Entity, proof_state::Column::ProofId)),
                        )
                        .to_owned(),
                )
                .into_condition(),
        )
        // fallback ordering
        .order_by_desc(proof::Column::CreatedDate)
        .order_by_desc(proof::Column::Id)
}

impl DataLayer {
    pub async fn get_proofs(
        &self,
        query_params: GetProofsQuery,
    ) -> Result<GetProofsResponse, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_select_proofs_query(
            Proof::find().with_list_query(&query_params, &Some(vec![proof_schema::Column::Name])),
            Some(query_params.organisation_id),
        );

        let items_count = query.to_owned().count(&self.db).await.map_err(|e| {
            tracing::error!(
                "Error while fetching items count for proofs. Error: {}",
                e.to_string()
            );
            DataLayerError::GeneralRuntimeError(e.to_string())
        })?;

        let combined_proofs = query
            .into_model::<ProofsCombined>()
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while proofs for proof list. Error: {}",
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        // We only do that to use load_many and match the order of the results.
        let proofs: Vec<proof::Model> = combined_proofs.iter().map(|proof| proof.into()).collect();

        let histories = proofs.load_many(ProofState, &self.db).await.map_err(|e| {
            tracing::error!(
                "Error while fetching proof histories for proof list. Error: {}",
                e.to_string()
            );
            DataLayerError::GeneralRuntimeError(e.to_string())
        })?;

        let models: Vec<(ProofsCombined, Vec<proof_state::Model>)> = combined_proofs
            .into_iter()
            .zip(histories.into_iter())
            .collect();

        Ok(GetProofsResponse {
            values: models
                .into_iter()
                .map(ProofsDetailResponse::from_models)
                .collect(),
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use time::OffsetDateTime;
    use uuid::Uuid;

    use crate::data_layer::{
        common_queries::insert_proof_state,
        data_model::{ProofRequestState, SortDirection, SortableProofColumn},
        entities::{claim_schema::Datatype, proof_state},
        get_proofs::GetProofsQuery,
        test_utilities::*,
        DataLayer,
    };

    struct TestData {
        pub data_layer: DataLayer,
        pub organisation_id: String,
        //               Id,     Did     State                           ProofSchema
        pub proofs: Vec<(String, String, proof_state::ProofRequestState, String)>,
    }

    impl TestData {
        async fn new() -> TestData {
            let data_layer = setup_test_data_layer_and_connection().await.unwrap();

            let organisation_id = insert_organisation_to_database(&data_layer.db, None)
                .await
                .unwrap();
            let issuer_did =
                insert_did(&data_layer.db, "did name", "did:issuer:1", &organisation_id)
                    .await
                    .unwrap();
            let verifier_did = insert_did(
                &data_layer.db,
                "did name",
                "did:verifier:1",
                &organisation_id,
            )
            .await
            .unwrap();
            let verifier_did2 = insert_did(
                &data_layer.db,
                "did name",
                "did:verifier:2",
                &organisation_id,
            )
            .await
            .unwrap();
            let credential_schema_id = insert_credential_schema_to_database(
                &data_layer.db,
                None,
                &organisation_id,
                "Schema1",
            )
            .await
            .unwrap();
            let new_claim_schemas: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
                .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
                .collect();
            insert_many_claims_schema_to_database(
                &data_layer.db,
                &credential_schema_id,
                &new_claim_schemas,
            )
            .await
            .unwrap();

            let credential_id =
                insert_credential(&data_layer.db, &credential_schema_id, &issuer_did)
                    .await
                    .unwrap();

            let proof_schema_id = insert_proof_schema_with_claims_to_database(
                &data_layer.db,
                None,
                &new_claim_schemas,
                &organisation_id,
                "ProofSchema1",
            )
            .await
            .unwrap();

            let proof_schema_id2 = insert_proof_schema_with_claims_to_database(
                &data_layer.db,
                None,
                &new_claim_schemas,
                &organisation_id,
                "ProofSchema2",
            )
            .await
            .unwrap();

            let claims = &new_claim_schemas
                .iter()
                .map(|cs| (cs.0, "value".to_string()))
                .collect();

            insert_many_claims_to_database(&data_layer.db, &credential_id, claims)
                .await
                .unwrap();

            let proof_id = insert_proof_request_to_database_with_claims(
                &data_layer.db,
                &verifier_did,
                None,
                &proof_schema_id,
                proof_state::ProofRequestState::Created,
                &claims.iter().map(|c| c.0.to_owned()).collect(),
            )
            .await
            .unwrap();

            let proof_id2 = insert_proof_request_to_database_with_claims(
                &data_layer.db,
                &verifier_did2,
                None,
                &proof_schema_id2,
                proof_state::ProofRequestState::Accepted,
                &claims.iter().map(|c| c.0.to_owned()).collect(),
            )
            .await
            .unwrap();

            Self {
                data_layer,
                organisation_id,
                proofs: vec![
                    (
                        proof_id,
                        "did:verifier:1".to_owned(),
                        proof_state::ProofRequestState::Created,
                        proof_schema_id,
                    ),
                    (
                        proof_id2,
                        "did:verifier:2".to_owned(),
                        proof_state::ProofRequestState::Accepted,
                        proof_schema_id2,
                    ),
                ],
            }
        }
    }

    #[tokio::test]
    async fn get_proofs_test_simple() {
        let test_data = TestData::new().await;

        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery::from_pagination(
                0,
                10,
                test_data.organisation_id.to_owned(),
            ))
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap();
        assert_eq!(2, proofs.total_items);
        assert_eq!(1, proofs.total_pages);

        for (proof_id, verifier_did, state, schema_id) in test_data.proofs {
            let proof = proofs.values.iter().find(|p| p.id == proof_id).unwrap();

            assert_eq!(proof.verifier_did, verifier_did);
            assert_eq!(proof.state, state.into());
            assert_eq!(proof.schema.id, schema_id);
        }
    }

    #[tokio::test]
    async fn get_proofs_test_dates_and_states() {
        let test_data = TestData::new().await;
        let (proof_id, _, _, _) = test_data.proofs[0].clone();

        let now = OffsetDateTime::now_utc();
        let later = now + time::Duration::seconds(1);

        insert_proof_state(
            &test_data.data_layer.db,
            &proof_id,
            now,
            now,
            proof_state::ProofRequestState::Offered,
        )
        .await
        .unwrap();

        insert_proof_state(
            &test_data.data_layer.db,
            &proof_id,
            later,
            later,
            proof_state::ProofRequestState::Accepted,
        )
        .await
        .unwrap();

        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery::from_pagination(
                0,
                10,
                test_data.organisation_id.to_owned(),
            ))
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap();

        let proof = proofs.values.iter().find(|p| p.id == proof_id).unwrap();

        assert_eq!(proof.state, ProofRequestState::Accepted);
        assert_eq!(proof.requested_date, Some(now));
        assert_eq!(proof.completed_date, Some(later));
    }

    #[tokio::test]
    async fn get_proofs_test_order_by_state() {
        let test_data = TestData::new().await;

        // Sort by state Descending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::State),
                sort_direction: Some(SortDirection::Descending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[0].0);
        assert_eq!(proofs[1].id, test_data.proofs[1].0);

        // Sort by state Ascending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::State),
                sort_direction: Some(SortDirection::Ascending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[1].0);
        assert_eq!(proofs[1].id, test_data.proofs[0].0);

        // Sort by Schema name descending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::ProofSchemaName),
                sort_direction: Some(SortDirection::Descending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[1].0);
        assert_eq!(proofs[1].id, test_data.proofs[0].0);

        // Sort by Schema name ascending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::ProofSchemaName),
                sort_direction: Some(SortDirection::Ascending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[0].0);
        assert_eq!(proofs[1].id, test_data.proofs[1].0);

        // Sort by Verifier did name descending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::VerifierDid),
                sort_direction: Some(SortDirection::Descending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[1].0);
        assert_eq!(proofs[1].id, test_data.proofs[0].0);

        // Sort by Verifier did name ascending
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: None,
                sort: Some(SortableProofColumn::VerifierDid),
                sort_direction: Some(SortDirection::Ascending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs[0].id, test_data.proofs[0].0);
        assert_eq!(proofs[1].id, test_data.proofs[1].0);

        // Filter by schema name
        let proofs = test_data
            .data_layer
            .get_proofs(GetProofsQuery {
                page: 0,
                page_size: 2,
                organisation_id: test_data.organisation_id.to_owned(),
                name: Some("ProofSchema1".to_owned()),
                sort: None,
                sort_direction: Some(SortDirection::Ascending),
            })
            .await;
        assert!(proofs.is_ok());
        let proofs = proofs.unwrap().values;
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].id, test_data.proofs[0].0);
    }
}
