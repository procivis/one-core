use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, DbErr, EntityTrait, QueryFilter, QuerySelect,
    RelationTrait, Select,
};

use crate::data_model::ProofSchemaResponseDTO;
use crate::endpoints::data_model::ClaimsCombined;
use crate::entities::{
    claim_schema, credential_schema, proof_schema, proof_schema_claim, ProofSchema,
    ProofSchemaClaim,
};

pub(crate) async fn get_proof_schema_details(
    db: &DatabaseConnection,
    uuid: &str,
) -> Result<ProofSchemaResponseDTO, DbErr> {
    let proof_schema: proof_schema::Model = get_base_query(uuid)
        .one(db)
        .await?
        .ok_or(DbErr::RecordNotFound("Record not found".to_string()))?;

    let claims = ProofSchemaClaim::find()
        .filter(
            Condition::all()
                .add(proof_schema_claim::Column::ProofSchemaId.eq(proof_schema.id.to_string())),
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

    Ok(ProofSchemaResponseDTO::from_model(proof_schema, claims))
}

fn get_base_query(uuid: &str) -> Select<ProofSchema> {
    ProofSchema::find_by_id(uuid).filter(proof_schema::Column::DeletedAt.is_null())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utilities::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_get_proof_schemas_simple() {
        let db = setup_test_database_and_connection().await.unwrap();

        let result = get_proof_schema_details(&db, &Uuid::new_v4().to_string()).await;
        assert!(result.is_err_and(|error| matches!(error, DbErr::RecordNotFound(_))));

        let uuid = insert_proof_schema_to_database(&db, None).await.unwrap();

        let result = get_proof_schema_details(&db, &uuid).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(uuid, response.id);
    }

    #[tokio::test]
    async fn test_get_proof_schemas_with_claims_and_credential_schemas() {
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

        let result = get_proof_schema_details(&db, &proof_schema_id).await;
        assert!(result.is_ok());

        let response = result.unwrap();
        assert_eq!(proof_schema_id, response.id);
        assert_eq!(3, response.claim_schemas.len());
        assert_eq!(
            credential_id,
            response.claim_schemas[0].credential_schema_id
        );
    }
}
