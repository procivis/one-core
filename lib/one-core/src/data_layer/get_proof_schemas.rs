use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Select};

use crate::data_layer::entities::{proof_schema, ProofSchema};
use crate::data_layer::list_query::{GetEntityColumn, SelectWithListQuery};
use crate::data_layer::{
    common::calculate_pages_count,
    data_model::{GetProofSchemaResponse, ProofSchemaResponse},
};
use crate::data_layer::{DataLayer, DataLayerError};

use super::common_queries;
use super::data_model::{GetListQueryParams, SortableProofSchemaColumn};

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

impl DataLayer {
    pub async fn get_proof_schemas(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaResponse, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_base_query()
            .with_organisation_id(&query_params, &proof_schema::Column::OrganisationId)
            .with_list_query(&query_params, &Some(vec![proof_schema::Column::Name]))
            .order_by_desc(proof_schema::Column::CreatedDate)
            .order_by_desc(proof_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let proof_schemas: Vec<proof_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let proof_ids = proof_schemas
            .iter()
            .map(|item| item.id.clone())
            .collect::<Vec<String>>();

        let claims = common_queries::fetch_proof_schema_claim_schemas(&self.db, &proof_ids).await?;

        Ok(GetProofSchemaResponse {
            values: proof_schemas
                .into_iter()
                .map(|proof_schema| {
                    let claims = claims
                        .iter()
                        .filter(|item| item.proof_schema_id == proof_schema.id)
                        .cloned()
                        .collect();

                    ProofSchemaResponse::from_model(proof_schema, claims)
                })
                .collect(),
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }
}

fn get_base_query() -> Select<ProofSchema> {
    ProofSchema::find().filter(proof_schema::Column::DeletedAt.is_null())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, Set};
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{proof_schema, GetProofSchemaQuery, SortableProofSchemaColumn};

    use crate::data_layer::test_utilities::*;

    #[tokio::test]
    async fn test_get_proof_schemas_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let _id = insert_proof_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                1,
                organisation_id.to_owned(),
            ))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_with_ordered_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let mut new_claims: Vec<(Uuid, bool, u32)> =
            (0..50).map(|i| (Uuid::new_v4(), i % 2 == 0, i)).collect();

        // Seems that sqlite keeps the order of insertion. We sort by UUID to mimic
        // MariaDB behaviour and reproduce unordered response
        new_claims.sort_by(|a, b| a.0.cmp(&b.0));

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let credential_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
                .await
                .unwrap();

        insert_many_claims_schema_to_database(&data_layer.db, &credential_id, &new_claims)
            .await
            .unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let proof_schema_id = insert_proof_schema_with_claims_to_database(
            &data_layer.db,
            None,
            &new_claims,
            &organisation_id,
        )
        .await
        .unwrap();

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                1,
                organisation_id.to_owned(),
            ))
            .await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(response.values[0].id, proof_schema_id);
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        let claims = response.values[0].claim_schemas.clone();
        assert_eq!(claims.len(), 50);

        // Now lets get back to the expected order and compare with the result
        new_claims.sort_by(|a, b| a.2.cmp(&b.2));

        assert!(new_claims
            .iter()
            .zip(claims.iter())
            .all(|(expected, result)| expected.0.to_string() == result.id
                && expected.1 == result.is_required
                && result.credential_schema_id == credential_id));
    }

    #[tokio::test]
    async fn test_get_proof_schemas_empty() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                1,
                Uuid::new_v4().to_string(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_deleted() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let predefined_deletion_date = Some(get_dummy_date());
        let _id = insert_proof_schema_to_database(
            &data_layer.db,
            predefined_deletion_date,
            &organisation_id,
        )
        .await
        .unwrap();

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                1,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_pages() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        for _ in 0..50 {
            let _id = insert_proof_schema_to_database(&data_layer.db, None, &organisation_id)
                .await
                .unwrap();
        }

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                10,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                1,
                10,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                5,
                10,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_proof_schemas_sorting() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let older_schema = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-01-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("older".to_string()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let newer_schema = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            name: Set("newer".to_string()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);

        // sort by name - Descending
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: Some(crate::data_layer::data_model::SortDirection::Descending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_schema.id, response.values[0].id);

        // sort by name - explicit Ascending
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::Name),
                sort_direction: Some(crate::data_layer::data_model::SortDirection::Ascending),
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);

        // sort by CreatedDate - default Ascending
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableProofSchemaColumn::CreatedDate),
                sort_direction: None,
                name: None,
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(older_schema.id, response.values[0].id);

        // no sorting specified - default Descending by CreatedDate
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery::from_pagination(
                0,
                2,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(2, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(2, response.values.len());
        assert_eq!(newer_schema.id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_proof_schemas_filtering() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let schema_a = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("a-schema".to_string()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let schema_capital_b = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("B-schema".to_string()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        // filter "a-"
        let mut filter_a_minus_query = GetProofSchemaQuery {
            page: 0,
            page_size: 3,
            sort: None,
            sort_direction: None,
            name: Some("a-".to_string()),
            organisation_id: organisation_id.to_owned(),
        };
        let result = data_layer
            .get_proof_schemas(filter_a_minus_query.clone())
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(schema_a.id, response.values[0].id);

        // filter "b-" (not matching case)
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("b-".to_string()),
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(schema_capital_b.id, response.values[0].id);

        // filter "schema" (not matching anything)
        let result = data_layer
            .get_proof_schemas(GetProofSchemaQuery {
                page: 0,
                page_size: 2,
                sort: None,
                sort_direction: None,
                name: Some("schema".to_string()),
                organisation_id: organisation_id.to_owned(),
            })
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());

        let other_organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let other_schema_a = proof_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            name: Set("a-schema".to_string()),
            organisation_id: Set(other_organisation_id.to_owned()),
            deleted_at: Set(None),
            expire_duration: Set(0),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        filter_a_minus_query.organisation_id = other_organisation_id;
        let result = data_layer.get_proof_schemas(filter_a_minus_query).await;

        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(other_schema_a.id, response.values[0].id);
    }
}
