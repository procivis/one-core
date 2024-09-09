use shared_types::{DidValue, ProofId};
use time::OffsetDateTime;

use super::dto::ConnectVerifierResponseDTO;
use super::mapper::proof_verifier_to_connect_verifier_response;
use super::utils::accept_proof;
use super::validator::validate_proof;
use super::SSIVerifierService;
use crate::common_mapper::get_or_create_did;
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::ExchangeType;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::DidRelations;
use crate::model::history::HistoryAction;
use crate::model::interaction::InteractionRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations};
use crate::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use crate::service::error::{EntityNotFoundError, ServiceError};
use crate::service::ssi_validator::{validate_config_entity_presence, validate_exchange_type};
use crate::util::history::log_history_event_proof;

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

                let _ = log_history_event_proof(
                    &*self.history_repository,
                    &proof,
                    HistoryAction::Errored,
                )
                .await;

                return Err(e);
            }
        };

        accept_proof(
            proof.clone(),
            proved_claims,
            holder_did,
            &*self.did_repository,
            &*self.credential_repository,
            &*self.proof_repository,
        )
        .await?;

        let _ = log_history_event_proof(&*self.history_repository, &proof, HistoryAction::Accepted)
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
                    verifier_did: Some(DidRelations {
                        keys: None,
                        organisation: Some(OrganisationRelations::default()),
                    }),
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

        let _ = log_history_event_proof(&*self.history_repository, &proof, HistoryAction::Rejected)
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

    use one_providers::credential_formatter::provider::MockCredentialFormatterProvider;
    use one_providers::did::provider::MockDidMethodProvider;
    use one_providers::key_algorithm::provider::MockKeyAlgorithmProvider;
    use one_providers::revocation::provider::MockRevocationMethodProvider;
    use uuid::Uuid;

    use super::*;
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
