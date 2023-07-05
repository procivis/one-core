use sea_orm::{ColumnTrait, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder, Select};

use crate::data_layer::entities::{credential_schema, CredentialSchema};
use crate::data_layer::list_query::{GetEntityColumn, SelectWithListQuery};
use crate::data_layer::{
    common::calculate_pages_count,
    data_model::{CredentialSchemaResponse, GetCredentialClaimSchemaResponse},
};
use crate::data_layer::{DataLayer, DataLayerError};

use super::common_queries;
use super::data_model::{GetListQueryParams, SortableCredentialSchemaColumn};

impl GetEntityColumn for SortableCredentialSchemaColumn {
    type Column = credential_schema::Column;
    fn get_column(&self) -> credential_schema::Column {
        match self {
            SortableCredentialSchemaColumn::Name => credential_schema::Column::Name,
            SortableCredentialSchemaColumn::Format => credential_schema::Column::Format,
            SortableCredentialSchemaColumn::CreatedDate => credential_schema::Column::CreatedDate,
        }
    }
}

pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumn>;

impl DataLayer {
    pub async fn get_credential_schemas(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialClaimSchemaResponse, DataLayerError> {
        let limit: u64 = query_params.page_size as u64;

        let query = get_base_query()
            .with_organisation_id(&query_params, &credential_schema::Column::OrganisationId)
            .with_list_query(&query_params, &Some(vec![credential_schema::Column::Name]))
            .order_by_desc(credential_schema::Column::CreatedDate)
            .order_by_desc(credential_schema::Column::Id);

        let items_count = query
            .to_owned()
            .count(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let schemas: Vec<credential_schema::Model> = query
            .all(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?;

        let schema_ids = schemas
            .iter()
            .map(|model| model.id.clone())
            .collect::<Vec<_>>();

        let claims =
            common_queries::fetch_credential_schema_claim_schemas(&self.db, schema_ids.as_slice())
                .await?;

        Ok(GetCredentialClaimSchemaResponse {
            values: schemas
                .into_iter()
                .map(|credential_schema| {
                    CredentialSchemaResponse::from_model(credential_schema, &claims)
                })
                .collect(),
            total_pages: calculate_pages_count(items_count, limit),
            total_items: items_count,
        })
    }
}

fn get_base_query() -> Select<CredentialSchema> {
    CredentialSchema::find().filter(credential_schema::Column::DeletedAt.is_null())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveModelTrait, Set};
    use time::macros::datetime;
    use uuid::Uuid;

    use super::{credential_schema, GetCredentialSchemaQuery, SortableCredentialSchemaColumn};

    use crate::data_layer::test_utilities::*;

    #[tokio::test]
    async fn test_get_credential_schemas_simple() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let _id = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
    async fn test_get_credential_schemas_with_ordered_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let claims_count: usize = 50;

        let mut new_claims: Vec<(Uuid, bool, u32)> = (0..claims_count)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i as u32))
            .collect();

        // Seems that sqlite keeps the order of insertion. We sort by UUID to mimic
        // MariaDB behaviour and reproduce unordered response
        new_claims.sort_by(|a, b| a.0.cmp(&b.0));

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let id = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(&data_layer.db, &id, &new_claims)
            .await
            .unwrap();

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
        assert_eq!(id, response.values[0].id);
        let claims = response.values[0].claims.clone();

        assert_eq!(claims.len(), claims_count);

        // Now lets get back to the expected order and compare with the result
        new_claims.sort_by(|a, b| a.2.cmp(&b.2));

        assert!(new_claims
            .iter()
            .zip(claims.iter())
            .all(|(expected, result)| expected.0.to_string() == result.id));
    }

    #[tokio::test]
    async fn test_get_credential_schemas_empty() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
    async fn test_get_credential_schemas_deleted() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let predefined_deletion_date = Some(get_dummy_date());
        let _id = insert_credential_schema_to_database(
            &data_layer.db,
            predefined_deletion_date,
            &organisation_id,
        )
        .await
        .unwrap();

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
    async fn test_get_credential_schemas_pages() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        for _ in 0..50 {
            let _id = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
                .await
                .unwrap();
        }

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
    async fn test_get_credential_schemas_sorting() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let older_jwt_schema = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-01-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            format: Set(credential_schema::Format::Jwt),
            name: Set("older".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let newer_sdjwt_schema = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            format: Set(credential_schema::Format::SdJwt),
            name: Set("newer".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(newer_sdjwt_schema.id, response.values[0].id);

        // sort by name - Descending
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);

        // sort by name - explicit Ascending
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(newer_sdjwt_schema.id, response.values[0].id);

        // sort by CreatedDate - default Ascending
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::CreatedDate),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);

        // sort by Format - default Ascending
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Format),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);

        // no sorting specified - default Descending by CreatedDate
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
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
        assert_eq!(newer_sdjwt_schema.id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_filtering() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let schema_a = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            format: Set(Default::default()),
            name: Set("a-schema".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        let schema_capital_b = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            format: Set(Default::default()),
            name: Set("B-schema".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(organisation_id.to_owned()),
            deleted_at: Set(None),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();

        // filter "a-"
        let mut filter_a_minus_query = GetCredentialSchemaQuery {
            page: 0,
            page_size: 3,
            sort: None,
            sort_direction: None,
            name: Some("a-".to_string()),
            organisation_id: organisation_id.to_owned(),
        };
        let result = data_layer
            .get_credential_schemas(filter_a_minus_query.clone())
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(schema_a.id, response.values[0].id);

        // filter "b-" (not matching case)
        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery {
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
            .get_credential_schemas(GetCredentialSchemaQuery {
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
        let other_schema_a = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            format: Set(Default::default()),
            name: Set("a-schema".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(other_organisation_id.to_owned()),
            deleted_at: Set(None),
        }
        .insert(&data_layer.db)
        .await
        .unwrap();
        filter_a_minus_query.organisation_id = other_organisation_id;
        let result = data_layer
            .get_credential_schemas(filter_a_minus_query)
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
        assert_eq!(other_schema_a.id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_multiple_claims_with_small_page_size() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let id = insert_credential_schema_to_database(&data_layer.db, None, &organisation_id)
            .await
            .unwrap();

        let new_claims: Vec<(Uuid, bool, u32)> =
            (0..4).map(|i| (Uuid::new_v4(), i % 2 == 0, i)).collect();

        insert_many_claims_schema_to_database(&data_layer.db, &id, &new_claims)
            .await
            .unwrap();

        let result = data_layer
            .get_credential_schemas(GetCredentialSchemaQuery::from_pagination(
                0,
                2,
                organisation_id.to_owned(),
            ))
            .await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());
        assert_eq!(4, response.values[0].claims.len());
    }
}
