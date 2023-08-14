use sea_orm::{EntityTrait, LoaderTrait, ModelTrait, QueryOrder, QuerySelect, RelationTrait};

use crate::data_layer::entities::{
    Claim, ClaimSchema, CredentialSchema, CredentialSchemaClaimSchema, Proof, ProofSchema,
};
use crate::data_layer::{DataLayer, DataLayerError};

use super::data_model::ProofDetailsResponse;
use super::entities::{
    claim, claim_schema, credential_schema, proof_schema_claim_schema, ProofState,
};

impl DataLayer {
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

        let claims = proof
            .find_related(Claim)
            .find_also_related(ClaimSchema)
            .order_by(
                proof_schema_claim_schema::Column::Order,
                sea_orm::Order::Asc,
            )
            .join_rev(
                sea_orm::JoinType::LeftJoin,
                proof_schema_claim_schema::Relation::ClaimSchema.def(),
            )
            .group_by(claim::Column::Id)
            .all(&self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching claims for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        let (claims, claim_schemas): (Vec<_>, Vec<_>) = claims.into_iter().unzip();
        let claim_schemas: Vec<claim_schema::Model> = claim_schemas.into_iter().flatten().collect();

        let mut credential_schemas = claim_schemas
            .load_many_to_many(CredentialSchema, CredentialSchemaClaimSchema, &self.db)
            .await
            .map_err(|e| {
                tracing::error!(
                    "Error while fetching credential schemas for proof {}. Error: {}",
                    uuid,
                    e.to_string()
                );
                DataLayerError::GeneralRuntimeError(e.to_string())
            })?;

        let credential_schemas: Vec<credential_schema::Model> = credential_schemas
            .iter_mut()
            .filter_map(|schemas| schemas.pop())
            .collect();

        if claims.len() != claim_schemas.len() || claim_schemas.len() != credential_schemas.len() {
            // Due to the fact that we have a hard relation between entities this should not happen
            // as long as database integrity is intact.
            tracing::debug!("Inconsistent lengths of responses. Data is missing.");
            return Err(DataLayerError::RecordNotFound);
        }

        let claims = claims
            .into_iter()
            .zip(claim_schemas.into_iter())
            .zip(credential_schemas.into_iter())
            .map(|((claim, claim_schema), credential_schema)| {
                (claim, claim_schema, credential_schema)
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

        Ok(ProofDetailsResponse::from_models(
            proof,
            history,
            proof_schema,
            claims,
        ))
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::data_layer::{
        entities::{claim_schema::Datatype, proof_state::ProofRequestState},
        test_utilities::{
            insert_credential, insert_credential_schema_to_database, insert_did,
            insert_many_claims_schema_to_database, insert_many_claims_to_database,
            insert_organisation_to_database, insert_proof_request_to_database_with_claims,
            insert_proof_schema_with_claims_to_database, setup_test_data_layer_and_connection,
        },
    };

    #[tokio::test]
    async fn test_get_proof_with_claims() {
        let data_layer = setup_test_data_layer_and_connection().await.unwrap();

        let organisation_id = insert_organisation_to_database(&data_layer.db, None)
            .await
            .unwrap();
        let issuer_did = insert_did(
            &data_layer.db,
            "did name",
            "did:issuer:123",
            &organisation_id,
        )
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
        let new_claim_schemas: Vec<(Uuid, bool, u32, Datatype)> = (0..4)
            .map(|i| (Uuid::new_v4(), i % 2 == 0, i, Datatype::String))
            .collect();
        insert_many_claims_schema_to_database(
            &data_layer.db,
            &credential_schema_id,
            &new_claim_schemas,
        )
        .await
        .unwrap();

        let credential_id = insert_credential(&data_layer.db, &credential_schema_id, &issuer_did)
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
            .map(|cs| (cs.0, "value".to_string()))
            .collect();

        insert_many_claims_to_database(&data_layer.db, &credential_id, claims)
            .await
            .unwrap();

        let proof_id = insert_proof_request_to_database_with_claims(
            &data_layer.db,
            &verifier_did,
            None,
            &proof_schema_id,
            ProofRequestState::Accepted,
            &claims.iter().map(|c| c.0.to_owned()).collect(),
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
        assert_eq!(response.claims[0].value, "value");
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
