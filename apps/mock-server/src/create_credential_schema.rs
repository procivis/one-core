use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, Set};
use time::OffsetDateTime;

use crate::data_model::CreateCredentialSchemaRequestDTO;

pub(crate) async fn create_credential_schema(
    db: &DatabaseConnection,
    request: CreateCredentialSchemaRequestDTO,
) -> Result<(), DbErr> {
    let now = OffsetDateTime::now_utc();

    let credential_schema = one_core::entities::credential_schema::ActiveModel {
        id: Default::default(),
        name: Set(request.name),
        created_date: Set(now),
        last_modified: Set(now),
        format: Set(request.format),
        deleted_at: Default::default(),
        revocation_method: Set(request.revocation_method),
        organisation_id: Set(0), // TODO: Set this correctly once organisation table is added
    }
    .insert(db)
    .await?;

    for claim_schema in request.claims {
        one_core::entities::claim_schema::ActiveModel {
            id: Default::default(),
            created_date: Set(now),
            last_modified: Set(now),
            key: Set(claim_schema.key),
            datatype: Set(claim_schema.datatype),
            credential_id: Set(credential_schema.id),
        }
        .insert(db)
        .await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::EntityTrait;

    use one_core::entities::claim_schema::Datatype;
    use one_core::entities::credential_schema::{Format, RevocationMethod};
    use one_core::entities::{claim_schema, credential_schema, ClaimSchema, CredentialSchema};

    use super::*;
    use crate::data_model::*;
    use crate::test_utilities::*;

    fn create_schema() -> CreateCredentialSchemaRequestDTO {
        CreateCredentialSchemaRequestDTO {
            name: "credential".to_string(),
            format: Format::Jwt,
            revocation_method: RevocationMethod::StatusList2021,
            organisation_id: "123".to_string(),
            claims: vec![
                CredentialClaimSchemaRequestDTO {
                    key: "1".to_string(),
                    datatype: Datatype::String,
                },
                CredentialClaimSchemaRequestDTO {
                    key: "2".to_string(),
                    datatype: Datatype::Number,
                },
            ],
        }
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
