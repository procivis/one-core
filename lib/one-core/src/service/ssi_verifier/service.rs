use super::{
    dto::{ConnectVerifierResponseDTO, ValidatedProofClaimDTO},
    mapper::proof_verifier_to_connect_verifier_response,
    validator::validate_proof,
    SSIVerifierService,
};
use crate::{
    common_mapper::did_from_did_document,
    common_validator::throw_if_latest_proof_state_not_eq,
    model::{
        claim::Claim,
        claim_schema::{ClaimSchemaId, ClaimSchemaRelations},
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        organisation::OrganisationRelations,
        proof::{Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    provider::did_method::provider::DidMethodProvider,
    service::{
        error::{EntityNotFoundError, ServiceError},
        ssi_validator::validate_config_entity_presence,
    },
};
use shared_types::DidValue;
use time::OffsetDateTime;
use uuid::Uuid;

impl SSIVerifierService {
    /// Holder connect to pick the proof request
    ///
    /// # Arguments
    ///
    /// * `proof_id` - proof identifier
    /// * `holder_did_value` - did as specified by the holder
    pub async fn connect_to_holder(
        &self,
        proof_id: &ProofId,
        holder_did_value: &DidValue,
        redirect_uri: &Option<String>,
    ) -> Result<ConnectVerifierResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                proof_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        ..Default::default()
                    }),
                    verifier_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*proof_id).into());
        };

        let did = proof.verifier_did.ok_or(ServiceError::MappingError(
            "verifier_did is None".to_string(),
        ))?;

        let proof_schema = proof
            .schema
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let result = proof_verifier_to_connect_verifier_response(
            proof_schema,
            redirect_uri.to_owned(),
            did,
        )?;

        self.set_holder_connected(proof_id, holder_did_value, &(*self.did_method_provider))
            .await?;

        Ok(result)
    }

    /// Proof submitted by user
    ///
    /// # Arguments
    ///
    /// * `proof_id` - proof identifier
    pub async fn submit_proof(
        &self,
        proof_id: &ProofId,
        presentation_content: &str,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .get_proof_with_state(
                proof_id,
                ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Offered)?;

        let proof_schema = proof.schema.ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;
        let holder_did = proof
            .holder_did
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?;

        let proved_claims = match validate_proof(
            proof_schema,
            holder_did,
            presentation_content,
            &*self.formatter_provider,
            self.key_algorithm_provider.clone(),
            self.did_method_provider.clone(),
            self.revocation_method_provider.clone(),
        )
        .await
        {
            Ok(claims) => claims,
            Err(e) => {
                self.fail_proof(proof_id).await?;
                return Err(e);
            }
        };

        self.accept_proof(proof_id, proved_claims).await
    }

    /// Proof rejected by user
    ///
    /// # Arguments
    ///
    /// * `proof_id` - proof identifier
    pub async fn reject_proof(&self, proof_id: &ProofId) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .get_proof_with_state(proof_id, ProofRelations::default())
            .await?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Offered)?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                proof_id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Rejected,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    // ======= PRIVATE METHODS

    /// Mark as offered
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    async fn set_holder_connected(
        &self,
        id: &ProofId,
        holder_did_value: &DidValue,
        did_method_provider: &(dyn DidMethodProvider + Send + Sync),
    ) -> Result<(), ServiceError> {
        let proof = self
            .get_proof_with_state(
                id,
                ProofRelations {
                    verifier_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let holder_did = match self
            .did_repository
            .get_did_by_value(holder_did_value, &DidRelations::default())
            .await?
        {
            Some(did) => did,
            None => {
                let organisation = proof
                    .verifier_did
                    .ok_or(ServiceError::MappingError(
                        "verifier_did is None".to_string(),
                    ))?
                    .organisation
                    .ok_or(ServiceError::MappingError(
                        "organisation is None".to_string(),
                    ))?;

                let did_document = did_method_provider.resolve(holder_did_value).await?;

                let resolved_did = did_from_did_document(&did_document, &organisation)?;

                self.did_repository.create_did(resolved_did.clone()).await?;

                resolved_did
            }
        };

        self.proof_repository
            .set_proof_holder_did(id, holder_did)
            .await?;

        let now = OffsetDateTime::now_utc();

        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Offered,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    /// Proof submit successful
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    async fn accept_proof(
        &self,
        id: &ProofId,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<(), ServiceError> {
        let claim_schema_ids: Vec<ClaimSchemaId> = proved_claims
            .iter()
            .map(|item| item.claim_schema_id)
            .collect();

        let claim_schemas = self
            .claim_schema_repository
            .get_claim_schema_list(claim_schema_ids, &ClaimSchemaRelations::default())
            .await?;

        let now = OffsetDateTime::now_utc();
        let claims: Vec<Claim> = proved_claims
            .into_iter()
            .zip(claim_schemas)
            .map(|(request, schema)| Claim {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                value: request.value,
                schema: Some(schema),
            })
            .collect();

        self.claim_repository
            .create_claim_list(claims.clone())
            .await?;
        self.proof_repository.set_proof_claims(id, claims).await?;

        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Accepted,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    /// Proof submit failed or another error occurred
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    async fn fail_proof(&self, id: &ProofId) -> Result<(), ServiceError> {
        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Error,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    /// Get latest proof state
    async fn get_proof_with_state(
        &self,
        id: &ProofId,
        relations: ProofRelations,
    ) -> Result<Proof, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    ..relations
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

        Ok(proof)
    }
}

// Private interface tests
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::{
        provider::{
            credential_formatter::provider::MockCredentialFormatterProvider,
            did_method::provider::MockDidMethodProvider,
            key_algorithm::provider::MockKeyAlgorithmProvider,
            revocation::provider::MockRevocationMethodProvider,
        },
        repository::{
            did_repository::MockDidRepository,
            mock::{
                claim_repository::MockClaimRepository,
                claim_schema_repository::MockClaimSchemaRepository,
                proof_repository::MockProofRepository,
            },
        },
        service::test_utilities::generic_config,
    };

    #[tokio::test]
    async fn test_fail_proof() {
        let proof_id = Uuid::new_v4();

        let mut proof_repository = MockProofRepository::new();
        proof_repository
            .expect_set_proof_state()
            .withf(move |_proof_id, _state| {
                assert_eq!(_proof_id, &proof_id);
                assert_eq!(_state.state, ProofStateEnum::Error);
                true
            })
            .once()
            .return_once(move |_, _| Ok(()));

        let service = SSIVerifierService {
            did_repository: Arc::new(MockDidRepository::new()),
            formatter_provider: Arc::new(MockCredentialFormatterProvider::new()),
            claim_schema_repository: Arc::new(MockClaimSchemaRepository::new()),
            proof_repository: Arc::new(proof_repository),
            claim_repository: Arc::new(MockClaimRepository::new()),
            did_method_provider: Arc::new(MockDidMethodProvider::new()),
            revocation_method_provider: Arc::new(MockRevocationMethodProvider::new()),
            key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
            config: Arc::new(generic_config().core),
        };

        let response = service.fail_proof(&proof_id).await;
        assert!(response.is_ok())
    }
}
