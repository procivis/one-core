use one_core::repository::{data_provider::ProofDetailsResponse, error::DataLayerError};
use sea_orm::{EntityTrait, LoaderTrait, ModelTrait, QueryOrder};

use crate::{
    data_model::proof_detail_response_from_models_with_claims,
    entity::{
        claim, claim_schema, credential_schema, proof_schema_claim_schema, Claim, ClaimSchema,
        CredentialSchema, CredentialSchemaClaimSchema, Did, Proof, ProofSchema,
        ProofSchemaClaimSchema, ProofState,
    },
    OldProvider,
};

impl OldProvider {
    pub async fn get_proof_details(
        &self,
        uuid: &str,
    ) -> Result<ProofDetailsResponse, DataLayerError> {
        let (proof, proof_schema) = Proof::find_by_id(uuid)
            .find_also_related(ProofSchema)
            .one(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .ok_or(DataLayerError::RecordNotFound)?;

        let proof_schema = proof_schema.ok_or(DataLayerError::RecordNotFound)?;

        let proof_claim_schemas = proof_schema
            .find_related(ProofSchemaClaimSchema)
            .order_by(
                proof_schema_claim_schema::Column::Order,
                sea_orm::Order::Asc,
            )
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching proof claims for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        let claim_schemas: Vec<claim_schema::Model> = proof_claim_schemas
            .load_one(ClaimSchema, &self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching claim schemas for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .into_iter()
            .flatten()
            .collect();

        let credential_schemas: Vec<credential_schema::Model> = claim_schemas
            .load_many_to_many(CredentialSchema, CredentialSchemaClaimSchema, &self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching credential schemas for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?
            .iter_mut()
            .filter_map(|schemas| schemas.pop())
            .collect();

        let claim_schemas_with_credential_schemas: Vec<(
            claim_schema::Model,
            credential_schema::Model,
        )> = claim_schemas
            .into_iter()
            .zip(credential_schemas.into_iter())
            .collect();

        let claims = proof.find_related(Claim).all(&self.db).await.map_err(|e| {
            tracing::error!(
                "Error while fetching claims for proof {}. Error: {}",
                uuid,
                e.to_string()
            );
            DataLayerError::GeneralRuntimeError(e.to_string())
        })?;

        if claims.len() > claim_schemas_with_credential_schemas.len() {
            // Due to the fact that we have a hard relation between entities this should not happen
            // as long as database integrity is intact.
            tracing::error!("Inconsistent lengths of claims and claim_schemas!");
            return Err(DataLayerError::GeneralRuntimeError(
                "Inconsistent lengths of claims and claim_schemas!".to_string(),
            ));
        }

        let claims: Vec<(
            Option<claim::Model>,
            claim_schema::Model,
            credential_schema::Model,
        )> = claim_schemas_with_credential_schemas
            .into_iter()
            .map(|(claim_schema, credential_schema)| {
                (
                    claims
                        .iter()
                        .find(|claim| claim.claim_schema_id == claim_schema.id)
                        .map(|claim| claim.to_owned()),
                    claim_schema,
                    credential_schema,
                )
            })
            .collect();

        let history = proof
            .find_related(ProofState)
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching state history for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        let verifier_did = Did::find_by_id(&proof.verifier_did_id)
            .one(&self.db)
            .await
            .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?
            .ok_or(DataLayerError::RecordNotFound)?;

        Ok(proof_detail_response_from_models_with_claims(
            proof,
            verifier_did,
            history,
            proof_schema,
            claims,
        ))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::{entity::proof_state::ProofRequestState, test_utilities::*};

    #[tokio::test]
    async fn test_get_proof_with_claims() {
        let data_layer = setup_test_data_provider_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();

        let verifier_did = insert_did(
            &data_layer.db,
            "did name",
            "did:verifier:123",
            &organisation_id,
        )
        .await
        .unwrap();
        let credential_schema_id =
            insert_credential_schema_to_database(&data_layer.db, None, &organisation_id, "test123")
                .await
                .unwrap();
        let new_claim_schemas: Vec<(Uuid, bool, u32, &str)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, "STRING"))
            .collect();
        insert_many_claims_schema_to_database(
            &data_layer.db,
            &credential_schema_id,
            &new_claim_schemas,
        )
        .await
        .unwrap();

        let proof_schema_name = "ProofSchema";
        let proof_schema_id = insert_proof_schema_with_claims_to_database(
            &data_layer.db,
            None,
            &new_claim_schemas,
            &organisation_id,
            proof_schema_name,
        )
        .await
        .unwrap();

        let claims = &new_claim_schemas
            .iter()
            .map(|cs| (Uuid::new_v4(), cs.0, "value".to_string()))
            .collect();

        let proof_id = insert_proof_request_to_database_with_claims(
            &data_layer.db,
            &verifier_did,
            None,
            &proof_schema_id,
            ProofRequestState::Accepted,
            claims,
        )
        .await
        .unwrap();

        let result = data_layer.get_proof_details(&proof_id).await;

        assert!(result.is_ok());

        let response = result.unwrap();

        assert_eq!(response.id, proof_id);
        assert_eq!(response.claims.len(), 4);
        assert_eq!(response.organisation_id, organisation_id);
        assert_eq!(response.schema.id, proof_schema_id);
        assert_eq!(response.schema.name, proof_schema_name);
        assert_eq!(response.claims[0].value, Some("value".to_string()));
        assert_eq!(
            response.claims[0].schema.id,
            new_claim_schemas[0].0.to_string()
        );
        assert_eq!(
            response.claims[1].schema.id,
            new_claim_schemas[1].0.to_string()
        );
        assert_eq!(
            response.claims[2].schema.id,
            new_claim_schemas[2].0.to_string()
        );
        assert_eq!(
            response.claims[3].schema.id,
            new_claim_schemas[3].0.to_string()
        );
        assert_eq!(
            response.claims[0].schema.credential_schema.id,
            credential_schema_id
        );
    }
}
