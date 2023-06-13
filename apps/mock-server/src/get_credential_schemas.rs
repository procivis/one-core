use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, LoaderTrait, PaginatorTrait, QueryFilter,
    Select,
};
use serde::Deserialize;
use utoipa::ToSchema;

use crate::data_model::{CredentialSchemaResponseDTO, GetCredentialClaimSchemaResponseDTO};
use crate::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};
use crate::list_query::{GetEntityColumn, GetListQueryParams, SelectWithListQuery};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

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

pub(crate) async fn get_credential_schemas(
    db: &DatabaseConnection,
    query_params: GetCredentialSchemaQuery,
) -> Result<GetCredentialClaimSchemaResponseDTO, DbErr> {
    let limit: u64 = query_params.page_size as u64;
    let items_count = get_base_query().count(db).await?;

    let schemas: Vec<credential_schema::Model> = get_base_query()
        .with_list_query(&query_params, &Some(vec![credential_schema::Column::Name]))
        .all(db)
        .await?;
    let claims: Vec<Vec<claim_schema::Model>> = schemas.load_many(ClaimSchema, db).await?;

    Ok(GetCredentialClaimSchemaResponseDTO {
        values: schemas
            .into_iter()
            .zip(claims)
            .map(|(credential_schema, claim_schemas)| {
                CredentialSchemaResponseDTO::from_model(credential_schema, claim_schemas)
            })
            .collect(),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

fn get_base_query() -> Select<CredentialSchema> {
    CredentialSchema::find().filter(credential_schema::Column::DeletedAt.is_null())
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
        calculate_pages_count, credential_schema, get_credential_schemas, GetCredentialSchemaQuery,
        SortableCredentialSchemaColumn,
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
    async fn test_get_credential_schemas_simple() {
        let db = setup_test_database_and_connection().await.unwrap();

        let _id = insert_credential_schema_to_database(&db, None)
            .await
            .unwrap();

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
    }

    #[tokio::test]
    async fn test_get_credential_schemas_empty() {
        let db = setup_test_database_and_connection().await.unwrap();

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_credential_schemas_deleted() {
        let db = setup_test_database_and_connection().await.unwrap();

        let predefined_deletion_date = Some(get_dummy_date());
        let _id = insert_credential_schema_to_database(&db, predefined_deletion_date)
            .await
            .unwrap();

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(0, 1)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(0, response.total_items);
        assert_eq!(0, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_credential_schemas_pages() {
        let db = setup_test_database_and_connection().await.unwrap();

        for _ in 0..50 {
            let _id = insert_credential_schema_to_database(&db, None)
                .await
                .unwrap();
        }

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(0, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(1, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(5, 10)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }

    #[tokio::test]
    async fn test_get_credential_schemas_sorting() {
        let db = setup_test_database_and_connection().await.unwrap();

        let older_jwt_schema = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-01-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            format: Set(credential_schema::Format::Jwt),
            name: Set("older".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        let newer_sdjwt_schema = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(datetime!(2023-02-01 21:00 +0)),
            last_modified: Set(get_dummy_date()),
            format: Set(credential_schema::Format::SdJwt),
            name: Set("newer".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        // sort by name - default Ascending
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(newer_sdjwt_schema.id, response.values[0].id);

        // sort by name - Descending
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);

        // sort by name - explicit Ascending
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Name),
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
        assert_eq!(newer_sdjwt_schema.id, response.values[0].id);

        // sort by CreatedDate - default Ascending
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::CreatedDate),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);

        // sort by Format - default Ascending
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
                page: 0,
                page_size: 2,
                sort: Some(SortableCredentialSchemaColumn::Format),
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
        assert_eq!(older_jwt_schema.id, response.values[0].id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_filtering() {
        let db = setup_test_database_and_connection().await.unwrap();

        let schema_a = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            format: Set(Default::default()),
            name: Set("a-schema".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        let schema_capital_b = credential_schema::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            created_date: Set(get_dummy_date()),
            last_modified: Set(get_dummy_date()),
            format: Set(Default::default()),
            name: Set("B-schema".to_string()),
            revocation_method: Set(Default::default()),
            organisation_id: Set(Default::default()),
            deleted_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();

        // filter "a-"
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
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
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
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
        let result = get_credential_schemas(
            &db,
            GetCredentialSchemaQuery {
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

    #[tokio::test]
    async fn test_get_credential_schemas_multiple_claims_with_small_page_size() {
        let db = setup_test_database_and_connection().await.unwrap();

        let id = insert_credential_schema_to_database(&db, None)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(
            &db,
            &id,
            &vec![
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
            ],
        )
        .await
        .unwrap();

        let result =
            get_credential_schemas(&db, GetCredentialSchemaQuery::from_pagination(0, 2)).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.values.len());
        assert_eq!(4, response.values[0].claims.len());
    }
}
