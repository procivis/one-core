use sea_orm::{DatabaseConnection, DbErr, EntityTrait, ModelTrait};

use crate::endpoints::data_model::CredentialSchemaResponseDTO;
use crate::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};

pub(crate) async fn get_credential_schema_details(
    db: &DatabaseConnection,
    uuid: &str,
) -> Result<CredentialSchemaResponseDTO, DbErr> {
    let schema: credential_schema::Model = CredentialSchema::find_by_id(uuid)
        .one(db)
        .await?
        .ok_or(DbErr::RecordNotFound("Record not found".to_string()))?;

    let claims: Vec<claim_schema::Model> = schema.find_related(ClaimSchema).all(db).await?;

    Ok(CredentialSchemaResponseDTO::from_model(schema, claims))
}

#[cfg(test)]
mod tests {
    use super::get_credential_schema_details;

    use crate::test_utilities::*;

    use sea_orm::DbErr;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_credential_schemas_simple() {
        let db = setup_test_database_and_connection().await.unwrap();

        const NON_EXISTING_UUID: &str = "ba439149-f313-4568-8dcb-8106bb518618";

        let result = get_credential_schema_details(&db, NON_EXISTING_UUID).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

        let uuid = insert_credential_schema_to_database(&db, None, &organisation_id)
            .await
            .unwrap();

        let result = get_credential_schema_details(&db, &uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }

    #[tokio::test]
    async fn test_get_credential_schemas_multiple_claims() {
        let db = setup_test_database_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&db, None).await.unwrap();

        let uuid = insert_credential_schema_to_database(&db, None, &organisation_id)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(
            &db,
            &uuid,
            &vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()],
        )
        .await
        .unwrap();

        let result = get_credential_schema_details(&db, &uuid).await;
        assert!(result.is_ok());
        let response = result.unwrap();
        assert_eq!(uuid, response.id);
        assert_eq!(3, response.claims.len());
    }
}
