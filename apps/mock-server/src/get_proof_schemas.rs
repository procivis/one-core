use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, RelationTrait, Select,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::data_model::{ClaimsCombined, GetProofSchemaResponseDTO, ProofSchemaResponseDTO};
use crate::entities::{
    claim_schema, credential_schema, proof_schema, proof_schema_claim, ProofSchema,
    ProofSchemaClaim,
};
use crate::list_query::{GetEntityColumn, GetListQueryParams, SelectWithListQuery};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

impl GetEntityColumn for SortableProofSchemaColumn {
    type Column = proof_schema::Column;
    fn get_column(&self) -> proof_schema::Column {
        match self {
            SortableProofSchemaColumn::Name => proof_schema::Column::Name,
            SortableProofSchemaColumn::CreatedDate => proof_schema::Column::CreatedDate,
        }
    }
}

pub type GetProofSchemaQuery = GetListQueryParams<SortableProofSchemaColumn>;

pub(crate) async fn get_proof_schemas(
    db: &DatabaseConnection,
    query_params: GetProofSchemaQuery,
) -> Result<GetProofSchemaResponseDTO, DbErr> {
    let limit: u64 = query_params.page_size as u64;
    let items_count = get_base_query().count(db).await?;

    let default_order = match query_params.sort {
        Some(_) => None,
        None => Some(proof_schema::Column::CreatedDate),
    };

    let values: Vec<proof_schema::Model> = get_base_query()
        .apply_if(default_order, QueryOrder::order_by_desc)
        .with_list_query(&query_params, &Some(vec![proof_schema::Column::Name]))
        .all(db)
        .await?;

    let claims = ProofSchemaClaim::find()
        .filter(
            Condition::all().add(
                proof_schema_claim::Column::ProofSchemaId.is_in(
                    values
                        .iter()
                        .map(|item| item.id.clone())
                        .collect::<Vec<String>>(),
                ),
            ),
        )
        .select_only()
        .columns([
            proof_schema_claim::Column::ClaimSchemaId,
            proof_schema_claim::Column::ProofSchemaId,
            proof_schema_claim::Column::IsRequired,
        ])
        .column_as(claim_schema::Column::Key, "claim_key")
        .column_as(credential_schema::Column::Id, "credential_id")
        .column_as(credential_schema::Column::Name, "credential_name")
        .join(
            sea_orm::JoinType::LeftJoin,
            proof_schema_claim::Relation::ClaimSchema.def(),
        )
        .join(
            sea_orm::JoinType::LeftJoin,
            claim_schema::Relation::CredentialSchema.def(),
        )
        .into_model::<ClaimsCombined>()
        .all(db)
        .await?;

    Ok(GetProofSchemaResponseDTO {
        values: values
            .into_iter()
            .map(|proof_schema| {
                let claims = claims
                    .iter()
                    .filter(|item| item.proof_schema_id == proof_schema.id)
                    .cloned()
                    .collect();

                ProofSchemaResponseDTO::from_model(proof_schema, claims)
            })
            .collect(),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

fn get_base_query() -> Select<ProofSchema> {
    ProofSchema::find().filter(proof_schema::Column::DeletedAt.is_null())
}

fn calculate_pages_count(total_items_count: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return 0;
    }

    (total_items_count / page_size) + std::cmp::min(total_items_count % page_size, 1)
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, Set};
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{
        calculate_pages_count, get_proof_schemas, proof_schema, GetProofSchemaQuery,
        SortableProofSchemaColumn,
    };

    use crate::test_utilities::*;

    #[test]
    fn test_calculate_pages_count() {
        assert_eq!(0, calculate_pages_count(1, 0));

        assert_eq!(1, calculate_pages_count(1, 1));
        assert_eq!(1, calculate_pages_count(1, 2));
        assert_eq!(1, calculate_pages_count(1, 100));

        assert_eq!(5, calculate_pages_count(50, 10));
        assert_eq!(6, calculate_pages_count(51, 10));
        assert_eq!(6, calculate_pages_count(52, 10));
        assert_eq!(6, calculate_pages_count(60, 10));
        assert_eq!(7, calculate_pages_count(61, 10));
    }

    #[tokio::test]
    async fn test_get_proof_schemas_simple() {
        let db = setup_test_database_and_connection().await.unwrap();

        let _id = insert_proof_schema_to_database(&db, None).await.unwrap();

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_with_claims() {
        let db = setup_test_database_and_connection().await.unwrap();

        let new_claims = vec![
            (Uuid::new_v4(), true),
            (Uuid::new_v4(), false),
            (Uuid::new_v4(), true),
        ];

        let credential_id = insert_credential_schema_to_database(&db, None)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(
            &db,
            &credential_id,
            &new_claims.iter().map(|item| item.0).collect(),
        )
        .await
        .unwrap();

        let proof_schema_id = insert_proof_with_claims_schema_to_database(&db, None, &new_claims)
            .await
            .unwrap();

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.values[0].id, proof_schema_id);
        assert_eq!(response.values[0].id, proof_schema_id);
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        let claims = response.values[0].claim_schemas.clone();

        assert!(new_claims.iter().all(|(claim_id, is_required)| {
            if let Some(claim) = claims.iter().find(|claim| claim.id == claim_id.to_string()) {
                claim.is_required == *is_required && claim.credential_schema_id == credential_id
            } else {
                false
            }
        }));
    }

    #[tokio::test]
    async fn test_get_proof_schemas_empty() {
        let db: sea_orm::DatabaseConnection = setup_test_database_and_connection().await.unwrap();

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_deleted() {
        let db = setup_test_database_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());
        let _id = insert_proof_schema_to_database(&db, predefined_deletion_date)
            .await
            .unwrap();

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_pages() {
        let db = setup_test_database_and_connection().await.unwrap();

        for _ in 0..50 {
            let _id = insert_proof_schema_to_database(&db, None).await.unwrap();
        }

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(1, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(5, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_sorting() {
        let db = setup_test_database_and_connection().await.unwrap();

        let older_schema = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-01-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("older".to_string()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&db)
        .await
        .unwrap();

        let newer_schema = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("newer".to_string()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: None,
                name: None,
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);

        // sort by name - Descending
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: Some(crate::list_query::SortDirection::Descending),
                name: None,
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_schema.id, response.values[0].id);

        // sort by name - explicit Ascending
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: Some(crate::list_query::SortDirection::Ascending),
                name: None,
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);

        // sort by CreatedDate - default Ascending
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::CreatedDate),
                sort_direction: None,
                name: None,
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_schema.id, response.values[0].id);

        // no sorting specified - default Descending by CreatedDate
        let result = get_proof_schemas(&db, GetProofSchemaQuery::from_pagination(0, 2)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_proof_schemas_filtering() {
        let db = setup_test_database_and_connection().await.unwrap();

        let schema_a = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("a-schema".to_string()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&db)
        .await
        .unwrap();

        let schema_capital_b = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("B-schema".to_string()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&db)
        .await
        .unwrap();

        // filter "a-"
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("a-".to_string()),
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(schema_a.id, response.values[0].id);

        // filter "b-" (not matching case)
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("b-".to_string()),
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(schema_capital_b.id, response.values[0].id);

        // filter "schema" (not matching anything)
        let result = get_proof_schemas(
            &db,
            GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("schema".to_string()),
            },
        )
        .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(0, response.values.len());
    }
}
