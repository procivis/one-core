use chrono::Utc;
use one_core::data_model::CreateCredentialSchemaRequestDTO;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, Set};

pub(crate) async fn create_credential_schema(
    db: &DatabaseConnection,
    request: CreateCredentialSchemaRequestDTO,
) -> Result<(), DbErr> {
    let now = Utc::now();

    let credential_schema = one_core::entities::credential_schema::ActiveModel {
        id: Default::default(),
        name: Set(request.name),
        createdDate: Set(now),
        lastModified: Set(now),
        format: Set(request.format),
        deletedAt: Default::default(),
        revocationMethod: Set(request.revocation_method),
    }
    .insert(db)
    .await?;

    for claim_schema in request.claims {
        one_core::entities::claim_schema::ActiveModel {
            id: Default::default(),
            createdDate: Set(now),
            lastModified: Set(now),
            key: Set(claim_schema.key),
            datatype: Set(claim_schema.datatype),
            credentialId: Set(credential_schema.id),
        }
        .insert(db)
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use migration::{Migrator, MigratorTrait};
    use one_core::data_model::*;
    use one_core::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};
    use sea_orm::EntityTrait;

    fn create_schema() -> CreateCredentialSchemaRequestDTO {
        CreateCredentialSchemaRequestDTO {
            name: "credential".to_string(),
            format: Format::JWT,
            revocation_method: RevocationMethod::STATUSLIST2021,
            organisation_id: "123".to_string(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "1".to_string(),
                    datatype: Datatype::STRING,
                },
                CredentialClaimSchemaRequestDTO {
                    key: "2".to_string(),
                    datatype: Datatype::NUMBER,
                },
            ],
        }
    }

    async fn setup_test_database_and_connection() -> Result<DatabaseConnection, DbErr> {
        let db = sea_orm::Database::connect("sqlite::memory:").await?;
        Migrator::up(&db, None).await?;
        Ok(db)
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_without_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let credential_schemas_count = CredentialSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, credential_schemas_count);

        let mut schema = create_schema();
        schema.claims.clear();

        assert!(create_credential_schema(&database, schema).await.is_ok());

        let credential_schemas_count = CredentialSchema::find().all(&database).await.unwrap().len();
        assert_eq!(1, credential_schemas_count);
    }

    #[tokio::test]
    async fn create_credential_schema_test_simple_with_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let credential_schemas_count = CredentialSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, credential_schemas_count);
        let claim_schemas_count = ClaimSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, claim_schemas_count);

        assert!(create_credential_schema(&database, create_schema())
            .await
            .is_ok());

        let credential_schemas_count = CredentialSchema::find().all(&database).await.unwrap().len();
        assert_eq!(1, credential_schemas_count);
        let claim_schemas_count = ClaimSchema::find().all(&database).await.unwrap().len();
        assert_eq!(2, claim_schemas_count);
    }

    #[tokio::test]
    async fn create_credential_schema_test_related_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        assert!(create_credential_schema(&database, create_schema())
            .await
            .is_ok());
        assert!(create_credential_schema(&database, create_schema())
            .await
            .is_ok());
        assert!(create_credential_schema(&database, create_schema())
            .await
            .is_ok());

        let schemas: Vec<(credential_schema::Model, Vec<claim_schema::Model>)> =
            CredentialSchema::find()
                .find_with_related(ClaimSchema)
                .all(&database)
                .await
                .unwrap();
        assert_eq!(3, schemas.len());
        assert_eq!(2, schemas[0].1.len());
        assert_eq!(2, schemas[1].1.len());
        assert_eq!(2, schemas[2].1.len());
    }
}
