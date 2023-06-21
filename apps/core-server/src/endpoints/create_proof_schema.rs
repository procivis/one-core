use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, Set};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    endpoints::data_model::{CreateProofSchemaRequestDTO, CreateProofSchemaResponseDTO},
    entities::{proof_schema, proof_schema_claim},
};

pub(crate) async fn create_proof_schema(
    db: &DatabaseConnection,
    request: CreateProofSchemaRequestDTO,
) -> Result<CreateProofSchemaResponseDTO, DbErr> {
    let now = OffsetDateTime::now_utc();

    let proof_schema = proof_schema::ActiveModel {
        id: Set(Uuid::new_v4().to_string()),
        name: Set(request.name),
        deleted_at: Set(None),
        created_date: Set(now),
        last_modified: Set(now),
        organisation_id: Set(request.organisation_id.to_string()),
        expire_duration: Set(request.expire_duration),
    }
    .insert(db)
    .await?;

    for claim_schema in request.claim_schemas {
        proof_schema_claim::ActiveModel {
            claim_schema_id: Set(claim_schema.id.to_string()),
            proof_schema_id: Set(proof_schema.id.clone()),
            is_required: Set(false),
        }
        .insert(db)
        .await?;
    }

    Ok(CreateProofSchemaResponseDTO {
        id: proof_schema.id,
    })
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbErr, EntityTrait};
    use uuid::Uuid;

    use super::*;
    use crate::data_model::{ClaimProofSchemaRequestDTO, CreateProofSchemaRequestDTO};
    use crate::entities::{ProofSchema, ProofSchemaClaim};
    use crate::test_utilities::{
        insert_credential_schema_to_database, insert_many_claims_schema_to_database,
        insert_organisation_to_database, setup_test_database_and_connection,
    };

    fn create_schema() -> CreateProofSchemaRequestDTO {
        CreateProofSchemaRequestDTO {
            name: String::from("ProofSchema1"),
            organisation_id: Uuid::new_v4(),
            expire_duration: 10,
            claim_schemas: vec![],
        }
    }

    #[tokio::test]
    async fn create_proof_schema_test_simple_without_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schema_claim_count);

        let mut request = create_schema();

        request.organisation_id = Uuid::new_v4();

        insert_organisation_to_database(&database, Some(request.organisation_id))
            .await
            .unwrap();

        let response = create_proof_schema(&database, request).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.unwrap().id).is_ok());

        let proof_schemas_count = ProofSchema::find().all(&database).await.unwrap().len();
        assert_eq!(1, proof_schemas_count);
    }

    #[tokio::test]
    async fn create_proof_schema_test_with_not_existing_claim() {
        let database = setup_test_database_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schema_claim_count);

        let mut request = create_schema();
        request.claim_schemas = vec![ClaimProofSchemaRequestDTO { id: Uuid::new_v4() }];

        let response = create_proof_schema(&database, request.clone()).await;
        assert!(response.is_err());
        assert!(matches!(response, Err(DbErr::Exec(_))))
    }

    #[tokio::test]
    async fn create_proof_schema_test_with_claims() {
        let database = setup_test_database_and_connection().await.unwrap();

        let proof_schemas_count = ProofSchema::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schemas_count);

        let proof_schema_claim_count = ProofSchemaClaim::find().all(&database).await.unwrap().len();
        assert_eq!(0, proof_schema_claim_count);

        let claim_ids = vec![Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()];

        let organisation_id = insert_organisation_to_database(&database, None)
            .await
            .unwrap();

        let credential_id = insert_credential_schema_to_database(&database, None, &organisation_id)
            .await
            .unwrap();

        insert_many_claims_schema_to_database(&database, &credential_id, &claim_ids)
            .await
            .unwrap();

        let mut request = create_schema();
        request.claim_schemas = vec![
            ClaimProofSchemaRequestDTO { id: claim_ids[0] },
            ClaimProofSchemaRequestDTO { id: claim_ids[1] },
            ClaimProofSchemaRequestDTO { id: claim_ids[2] },
        ];

        insert_organisation_to_database(&database, Some(request.organisation_id))
            .await
            .unwrap();

        let response = create_proof_schema(&database, request.clone()).await;
        assert!(response.is_ok());
        assert!(Uuid::parse_str(&response.as_ref().unwrap().id).is_ok());

        let proof_schema_claims = ProofSchemaClaim::find().all(&database).await.unwrap();
        assert_eq!(3, proof_schema_claims.len());

        assert!(proof_schema_claims
            .into_iter()
            .enumerate()
            .all(|(i, item)| {
                item.claim_schema_id == request.claim_schemas[i].id.to_string()
                    && item.proof_schema_id == response.as_ref().unwrap().id
            }));
    }
}
