use sea_orm::{DatabaseConnection, DbErr, EntityTrait, PaginatorTrait, QuerySelect};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::data_model::{CredentialSchemaResponseDTO, GetCredentialClaimSchemaResponseDTO};
use one_core::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
#[serde(rename_all = "camelCase")]
pub struct GetCredentialSchemaQuery {
    pub page: u32,
    pub page_size: u32,
}

pub(crate) async fn get_credential_schemas(
    db: &DatabaseConnection,
    page: u32,
    page_size: u32,
) -> Result<GetCredentialClaimSchemaResponseDTO, DbErr> {
    let limit: u64 = page_size as u64;
    let offset: u64 = (page * page_size) as u64;

    let items_count = CredentialSchema::find().count(db).await?;
    let values: Vec<(credential_schema::Model, Vec<claim_schema::Model>)> =
        CredentialSchema::find()
            .find_with_related(ClaimSchema)
            .offset(Some(offset))
            .limit(Some(limit))
            .all(db)
            .await?;

    Ok(GetCredentialClaimSchemaResponseDTO {
        values: values
            .into_iter()
            .map(|(credential_schema, claim_schemas)| {
                CredentialSchemaResponseDTO::from_model(credential_schema, claim_schemas)
            })
            .collect(),
        total_pages: calculate_pages_count(items_count, limit),
        total_items: items_count,
    })
}

fn calculate_pages_count(total_items_count: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return 0;
    }

    (total_items_count / page_size) + std::cmp::min(total_items_count % page_size, 1)
}

#[cfg(test)]
mod tests {
    use super::{calculate_pages_count, get_credential_schemas};

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

        let result = get_credential_schemas(&db, 0, 1).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(1, response.total_items);
        assert_eq!(1, response.total_pages);
        assert_eq!(1, response.values.len());
    }

    #[tokio::test]
    async fn test_get_credential_schemas_pages() {
        let db = setup_test_database_and_connection().await.unwrap();

        for _ in 0..50 {
            let _id = insert_credential_schema_to_database(&db, None)
                .await
                .unwrap();
        }

        let result = get_credential_schemas(&db, 0, 10).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = get_credential_schemas(&db, 1, 10).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(10, response.values.len());

        let result = get_credential_schemas(&db, 5, 10).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(50, response.total_items);
        assert_eq!(5, response.total_pages);
        assert_eq!(0, response.values.len());
    }
}
