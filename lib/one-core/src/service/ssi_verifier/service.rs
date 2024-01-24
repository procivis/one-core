use std::collections::HashMap;

use super::{
    dto::{ConnectVerifierResponseDTO, ValidatedProofClaimDTO},
    mapper::proof_verifier_to_connect_verifier_response,
    validator::validate_proof,
    SSIVerifierService,
};
use crate::{
    common_mapper::{extracted_credential_to_model, get_or_create_did},
    common_validator::throw_if_latest_proof_state_not_eq,
    model::{
        claim::Claim,
        claim_schema::ClaimSchema,
        credential_schema::{CredentialSchema, CredentialSchemaId, CredentialSchemaRelations},
        did::DidRelations,
        organisation::OrganisationRelations,
        proof::{Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    provider::credential_formatter::model::DetailCredential,
    service::{
        error::{EntityNotFoundError, ServiceError},
        ssi_validator::validate_config_entity_presence,
    },
};
use shared_types::DidValue;
use time::OffsetDateTime;

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
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    state: Some(ProofStateRelations::default()),
                    verifier_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*proof_id).into());
        };

        let did = proof
            .verifier_did
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "verifier_did is None".to_string(),
            ))?;

        let proof_schema = proof
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let result = proof_verifier_to_connect_verifier_response(
            proof_schema.to_owned(),
            redirect_uri.to_owned(),
            did.to_owned(),
        )?;

        self.set_holder_connected(proof, holder_did_value).await?;

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
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;
        let holder_did = proof
            .holder_did
            .as_ref()
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

        self.accept_proof(proof, proved_claims).await
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

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

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
        proof: Proof,
        holder_did_value: &DidValue,
    ) -> Result<(), ServiceError> {
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;

        let holder_did = get_or_create_did(
            &*self.did_repository,
            &proof_schema.organisation,
            holder_did_value,
        )
        .await?;

        self.proof_repository
            .set_proof_holder_did(&proof.id, holder_did)
            .await?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Requested,
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
        proof: Proof,
        proved_claims: Vec<ValidatedProofClaimDTO>,
    ) -> Result<(), ServiceError> {
        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;

        let claim_schemas =
            proof_schema
                .claim_schemas
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "proof schema claims is None".to_string(),
                ))?;

        struct ProvedClaim {
            claim_schema: ClaimSchema,
            value: String,
            credential: DetailCredential,
            credential_schema: CredentialSchema,
        }
        let proved_claims = proved_claims
            .into_iter()
            .map(|proved_claim| {
                let claim_schema = claim_schemas
                    .iter()
                    .find(|claim_schema| claim_schema.schema.id == proved_claim.claim_schema_id)
                    .ok_or(ServiceError::MappingError(
                        "Couldn't find matching proof claim schema".to_string(),
                    ))?
                    .to_owned();
                Ok(ProvedClaim {
                    value: proved_claim.value,
                    credential: proved_claim.credential,
                    credential_schema: claim_schema.credential_schema.ok_or(
                        ServiceError::MappingError("credential schema is None".to_string()),
                    )?,
                    claim_schema: claim_schema.schema,
                })
            })
            .collect::<Result<Vec<ProvedClaim>, ServiceError>>()?;

        let mut claims_per_credential: HashMap<CredentialSchemaId, Vec<ProvedClaim>> =
            HashMap::new();
        for proved_claim in proved_claims {
            claims_per_credential
                .entry(proved_claim.credential_schema.id)
                .or_default()
                .push(proved_claim);
        }

        let holder_did = proof
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;

        let mut proof_claims: Vec<Claim> = vec![];
        for (_, credential_claims) in claims_per_credential {
            let claims: Vec<(String, ClaimSchema)> = credential_claims
                .iter()
                .map(|claim| (claim.value.to_owned(), claim.claim_schema.to_owned()))
                .collect();

            let first_claim = credential_claims
                .first()
                .ok_or(ServiceError::MappingError("claims are empty".to_string()))?;
            let issuer_did =
                first_claim
                    .credential
                    .issuer_did
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "issuer_did is missing".to_string(),
                    ))?;
            let issuer_did = get_or_create_did(
                &*self.did_repository,
                &proof_schema.organisation,
                issuer_did,
            )
            .await?;

            let credential = extracted_credential_to_model(
                first_claim.credential_schema.to_owned(),
                claims,
                issuer_did,
                holder_did.to_owned(),
            );

            proof_claims.append(
                &mut credential
                    .claims
                    .as_ref()
                    .ok_or(ServiceError::MappingError("claims missing".to_string()))?
                    .to_owned(),
            );

            self.credential_repository
                .create_credential(credential)
                .await?;
        }

        self.proof_repository
            .set_proof_claims(&proof.id, proof_claims)
            .await?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
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

    use uuid::Uuid;

    use super::*;
    use crate::{
        provider::{
            credential_formatter::provider::MockCredentialFormatterProvider,
            did_method::provider::MockDidMethodProvider,
            key_algorithm::provider::MockKeyAlgorithmProvider,
            revocation::provider::MockRevocationMethodProvider,
        },
        repository::{
            credential_repository::MockCredentialRepository, did_repository::MockDidRepository,
            mock::proof_repository::MockProofRepository,
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
            proof_repository: Arc::new(proof_repository),
            did_method_provider: Arc::new(MockDidMethodProvider::new()),
            credential_repository: Arc::new(MockCredentialRepository::new()),
            revocation_method_provider: Arc::new(MockRevocationMethodProvider::new()),
            key_algorithm_provider: Arc::new(MockKeyAlgorithmProvider::new()),
            config: Arc::new(generic_config().core),
        };

        let response = service.fail_proof(&proof_id).await;
        assert!(response.is_ok())
    }
}
