use super::{
    dto::{
        CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO, ProofDetailResponseDTO,
        ProofId,
    },
    mapper::{get_holder_proof_detail, get_verifier_proof_detail, proof_from_create_request},
    ProofService,
};
use crate::{
    common_mapper::list_response_try_into,
    config::validator::exchange::validate_exchange_type,
    model::{
        claim::ClaimRelations,
        common::EntityShareResponseDTO,
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        interaction::InteractionRelations,
        proof::ProofClaimRelations,
        proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    service::error::ServiceError,
};
use crate::{
    common_validator::throw_if_latest_proof_state_not_eq, service::error::BusinessLogicError,
};
use crate::{model::credential::CredentialRelations, service::error::EntityNotFoundError};
use crate::{
    provider::transport_protocol::dto::PresentationDefinitionResponseDTO,
    service::error::MissingProviderError,
};
use time::OffsetDateTime;

impl ProofService {
    /// Returns details of a proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof(&self, id: &ProofId) -> Result<ProofDetailResponseDTO, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(Default::default()),
                        }),
                        organisation: Some(Default::default()),
                    }),
                    state: Some(Default::default()),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(Default::default()),
                        },
                        credential: Some(CredentialRelations {
                            state: Some(Default::default()),
                            claims: Some(ClaimRelations {
                                schema: Some(Default::default()),
                            }),
                            schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(Default::default()),
                                organisation: Some(Default::default()),
                            }),
                            issuer_did: Some(Default::default()),
                            holder_did: Some(Default::default()),
                            ..Default::default()
                        }),
                    }),
                    verifier_did: Some(Default::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(Default::default()),
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

        if proof.schema.is_some() {
            get_verifier_proof_detail(proof)
        } else {
            get_holder_proof_detail(proof)
        }
    }

    /// Returns presentation definition of proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof_presentation_definition(
        &self,
        id: &ProofId,
    ) -> Result<PresentationDefinitionResponseDTO, ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let Some(proof) = proof else {
            return Err(EntityNotFoundError::Proof(*id).into());
        };

        let holder_did = proof
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?;

        if holder_did.did_type.is_remote() {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "holder_did is remote".to_string(),
            }
            .into());
        }

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let transport = self
            .protocol_provider
            .get_protocol(&proof.transport)
            .ok_or(MissingProviderError::TransportProtocol(
                proof.transport.clone(),
            ))?;
        Ok(transport.get_presentation_definition(&proof).await?)
    }

    /// Returns list of proofs according to query
    ///
    /// # Arguments
    ///
    /// * `query` - query parameters
    pub async fn get_proof_list(
        &self,
        query: GetProofQueryDTO,
    ) -> Result<GetProofListResponseDTO, ServiceError> {
        let result = self
            .proof_repository
            .get_proof_list(query)
            .await
            .map_err(ServiceError::from)?;

        list_response_try_into(result)
    }

    /// Creates a new proof
    ///
    /// # Arguments
    ///
    /// * `request` - data
    pub async fn create_proof(
        &self,
        request: CreateProofRequestDTO,
    ) -> Result<ProofId, ServiceError> {
        validate_exchange_type(&request.transport, &self.config.exchange)?;

        let now = OffsetDateTime::now_utc();
        let proof_schema_id = request.proof_schema_id;
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(&proof_schema_id, &ProofSchemaRelations::default())
            .await?
            .ok_or(BusinessLogicError::MissingProofSchema { proof_schema_id })?;

        // ONE-843: cannot create proof based on deleted schema
        if proof_schema.deleted_at.is_some() {
            return Err(BusinessLogicError::ProofSchemaDeleted { proof_schema_id }.into());
        }

        let verifier_did = self
            .did_repository
            .get_did(&request.verifier_did_id, &DidRelations::default())
            .await?;

        let Some(verifier_did) = verifier_did else {
            return Err(EntityNotFoundError::Did(request.verifier_did_id).into());
        };

        if verifier_did.deactivated {
            return Err(BusinessLogicError::DidIsDeactivated(verifier_did.id).into());
        }

        if verifier_did.did_type.is_remote() {
            return Err(BusinessLogicError::IncompatibleDidType {
                reason: "verifier_did is remote".to_string(),
            }
            .into());
        }

        self.proof_repository
            .create_proof(proof_from_create_request(
                request,
                now,
                proof_schema,
                verifier_did,
            ))
            .await
            .map_err(ServiceError::from)
    }

    /// Request proof
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    /// * `base_url` - verifier base url
    pub async fn share_proof(&self, id: &ProofId) -> Result<EntityShareResponseDTO, ServiceError> {
        let (proof, proof_state) = self.get_proof_with_state(id).await?;

        let now = OffsetDateTime::now_utc();

        match proof_state {
            ProofStateEnum::Created => {
                self.proof_repository
                    .set_proof_state(
                        id,
                        ProofState {
                            created_date: now,
                            last_modified: now,
                            state: ProofStateEnum::Pending,
                        },
                    )
                    .await?;
            }
            ProofStateEnum::Pending => {}
            state => {
                return Err(BusinessLogicError::InvalidProofState { state }.into());
            }
        }

        let transport_instance = &self
            .config
            .exchange
            .get_fields(&proof.transport)
            .map_err(|err| {
                ServiceError::MissingTransportProtocol(format!("{}. {err}", proof.transport))
            })?
            .r#type()
            .to_string();

        let transport = self
            .protocol_provider
            .get_protocol(transport_instance)
            .ok_or(MissingProviderError::TransportProtocol(
                transport_instance.clone(),
            ))?;

        let url = transport.share_proof(&proof).await?;

        Ok(EntityShareResponseDTO { url })
    }

    // ============ Private methods

    /// Get latest proof state
    async fn get_proof_with_state(
        &self,
        id: &ProofId,
    ) -> Result<(Proof, ProofStateEnum), ServiceError> {
        let proof = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    ..Default::default()
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Proof(*id))?;

        let proof_states = proof
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = proof_states
            .first()
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .state
            .to_owned();
        Ok((proof, latest_state))
    }
}
