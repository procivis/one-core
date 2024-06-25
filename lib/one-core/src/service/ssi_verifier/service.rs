use std::collections::HashMap;

use shared_types::{CredentialSchemaId, DidValue, ProofId};
use time::OffsetDateTime;

use super::dto::{ConnectVerifierResponseDTO, ValidatedProofClaimDTO};
use super::mapper::{
    proof_accept_errored_history_event, proof_verifier_to_connect_verifier_response,
};
use super::validator::validate_proof;
use super::SSIVerifierService;
use crate::common_mapper::{extracted_credential_to_model, get_or_create_did};
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::ExchangeType;
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchema;
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{Did, DidRelations};
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations};
use crate::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchemaRelations, ProofSchemaClaimRelations,
    ProofSchemaRelations,
};
use crate::provider::credential_formatter::model::DetailCredential;
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::ssi_validator::{validate_config_entity_presence, validate_exchange_type};
use crate::service::ssi_verifier::mapper::{
    proof_accepted_history_event, proof_rejected_history_event,
};

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
        redirect_uri: &Option<String>,
    ) -> Result<ConnectVerifierResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof(
                proof_id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
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

        validate_exchange_type(
            ExchangeType::ProcivisTemporary,
            &self.config,
            &proof.exchange,
        )?;

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

        self.set_holder_connected(proof).await?;

        Ok(result)
    }

    /// Proof submitted by user
    ///
    /// # Arguments
    ///
    /// * `proof_id` - proof identifier
    pub async fn submit_proof(
        &self,
        proof_id: ProofId,
        did_value: DidValue,
        presentation_content: &str,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .get_proof_with_state(
                &proof_id,
                ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        validate_exchange_type(
            ExchangeType::ProcivisTemporary,
            &self.config,
            &proof.exchange,
        )?;

        let holder_did = get_or_create_did(
            self.did_repository.as_ref(),
            &proof
                .schema
                .as_ref()
                .and_then(|schema| schema.organisation.clone()),
            &did_value,
        )
        .await?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;

        let proved_claims = match validate_proof(
            proof_schema,
            &holder_did,
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
                self.fail_proof(&proof_id).await?;
                let _ = self
                    .history_repository
                    .create_history(proof_accept_errored_history_event(&proof))
                    .await;

                return Err(e);
            }
        };

        let _ = self
            .accept_proof(proof.clone(), proved_claims, holder_did)
            .await;

        let _ = self
            .history_repository
            .create_history(proof_accepted_history_event(&proof))
            .await;
        Ok(())
    }

    /// Proof rejected by user
    ///
    /// # Arguments
    ///
    /// * `proof_id` - proof identifier
    pub async fn reject_proof(&self, proof_id: &ProofId) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .get_proof_with_state(
                proof_id,
                ProofRelations {
                    verifier_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        validate_exchange_type(
            ExchangeType::ProcivisTemporary,
            &self.config,
            &proof.exchange,
        )?;

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
            .await?;

        let _ = self
            .history_repository
            .create_history(proof_rejected_history_event(&proof))
            .await;

        Ok(())
    }

    // ======= PRIVATE METHODS

    /// Mark as offered
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    async fn set_holder_connected(&self, proof: Proof) -> Result<(), ServiceError> {
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

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
        holder_did: Did,
    ) -> Result<(), ServiceError> {
        validate_exchange_type(
            ExchangeType::ProcivisTemporary,
            &self.config,
            &proof.exchange,
        )?;

        let proof_schema = proof.schema.as_ref().ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;

        let claim_schemas_with_cred_schemas =
            match proof_schema.input_schemas.as_ref() {
                Some(input_schemas) if !input_schemas.is_empty() => {
                    let mut res: Vec<(ProofInputClaimSchema, CredentialSchema)> = Vec::new();

                    let input_schemas =
                        proof_schema
                            .input_schemas
                            .as_ref()
                            .ok_or(ServiceError::MappingError(
                                "claim_schemas is None".to_string(),
                            ))?;

                    for input in input_schemas {
                        let proof_input_claim_schemas =
                            input
                                .claim_schemas
                                .as_ref()
                                .ok_or(ServiceError::MappingError(
                                    "claim_schemas is None".to_string(),
                                ))?;

                        for proof_input_claim_schema in proof_input_claim_schemas {
                            let credential_schema = input.credential_schema.as_ref().ok_or(
                                ServiceError::MappingError("credential schema is None".to_string()),
                            )?;
                            res.push((
                                proof_input_claim_schema.to_owned(),
                                credential_schema.to_owned(),
                            ))
                        }
                    }

                    res
                }

                _ => {
                    return Err(ServiceError::MappingError(
                        "proof input schemas are missing".to_string(),
                    ))
                }
            };

        struct ProvedClaim {
            claim_schema: ClaimSchema,
            value: (String, serde_json::Value),
            credential: DetailCredential,
            credential_schema: CredentialSchema,
        }
        let proved_claims = proved_claims
            .into_iter()
            .map(|proved_claim| {
                let (claim_schema, credential_schema) = claim_schemas_with_cred_schemas
                    .iter()
                    .find(|(claim_schema, _)| {
                        claim_schema.schema.id == proved_claim.claim_schema_id
                    })
                    .ok_or(ServiceError::MappingError(
                        "Couldn't find matching proof claim schema".to_string(),
                    ))?
                    .to_owned();
                Ok(ProvedClaim {
                    value: proved_claim.value,
                    credential: proved_claim.credential,
                    credential_schema,
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

        let mut proof_claims: Vec<Claim> = vec![];
        for (_, credential_claims) in claims_per_credential {
            let claims: Vec<(serde_json::Value, ClaimSchema)> = credential_claims
                .iter()
                .map(|claim| Ok((claim.value.1.to_owned(), claim.claim_schema.to_owned())))
                .collect::<Result<Vec<_>, ServiceError>>()?;

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
                &[],
                first_claim.credential_schema.to_owned(),
                claims,
                issuer_did,
                holder_did.clone(),
            )?;

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
            .set_proof_holder_did(&proof.id, holder_did)
            .await?;

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
    use crate::provider::credential_formatter::provider::MockCredentialFormatterProvider;
    use crate::provider::did_method::provider::MockDidMethodProvider;
    use crate::provider::key_algorithm::provider::MockKeyAlgorithmProvider;
    use crate::provider::revocation::provider::MockRevocationMethodProvider;
    use crate::repository::credential_repository::MockCredentialRepository;
    use crate::repository::did_repository::MockDidRepository;
    use crate::repository::history_repository::MockHistoryRepository;
    use crate::repository::proof_repository::MockProofRepository;
    use crate::service::test_utilities::generic_config;

    #[tokio::test]
    async fn test_fail_proof() {
        let proof_id = Uuid::new_v4().into();

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
            history_repository: Arc::new(MockHistoryRepository::new()),
            config: Arc::new(generic_config().core),
        };

        let response = service.fail_proof(&proof_id).await;
        assert!(response.is_ok())
    }
}
