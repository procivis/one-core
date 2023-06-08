use sea_orm::{DatabaseConnection, DbErr, EntityTrait, QuerySelect};

use crate::data_model::CredentialSchemaResponseDTO;
use crate::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};

pub(crate) async fn get_credential_schema_details(
    db: &DatabaseConnection,
    uuid: &str,
) -> Result<CredentialSchemaResponseDTO, DbErr> {
    let result: Vec<(credential_schema::Model, Vec<claim_schema::Model>)> =
        CredentialSchema::find_by_id(uuid)
            .find_with_related(ClaimSchema)
            .limit(1)
            .all(db)
            .await?;

    let (schema, claims): (credential_schema::Model, Vec<claim_schema::Model>) = result
        .into_iter()
        .next()
        .ok_or(DbErr::RecordNotFound("Record not found".to_string()))?;

    Ok(CredentialSchemaResponseDTO::from_model(schema, claims))
}

#[cfg(test)]
mod tests {
    use super::get_credential_schema_details;

    use crate::test_utilities::*;

    use sea_orm::DbErr;

    #[tokio::test]
    async fn test_get_credential_schemas_simple() {
        let db = setup_test_database_and_connection().await.unwrap();

        const NON_EXISTING_UUID: &str = "ba439149-f313-4568-8dcb-8106bb518618";

        let result = get_credential_schema_details(&db, NON_EXISTING_UUID).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let uuid = insert_credential_schema_to_database(&db, None)
            .await
            .unwrap();

        let result = get_credential_schema_details(&db, &uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }
}
