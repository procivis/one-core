use super::{
    dto::{
        CreateProofClaimRequestDTO, CreateProofRequestDTO, GetProofListResponseDTO,
        GetProofQueryDTO, ProofDetailResponseDTO, ProofId, ShareProofResponseDTO,
    },
    mapper::proof_from_create_request,
    ProofService,
};
use crate::{
    common_mapper::list_response_try_into,
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidRelations, DidType},
        organisation::OrganisationRelations,
        proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    repository::error::DataLayerError,
    service::{credential_schema::dto::ClaimSchemaId, error::ServiceError},
};
use time::OffsetDateTime;
use uuid::Uuid;

impl ProofService {
    /// Returns details of a proof
    ///
    /// # Arguments
    ///
    /// * `id` - Proof uuid
    pub async fn get_proof(&self, id: &ProofId) -> Result<ProofDetailResponseDTO, ServiceError> {
        let result = self
            .proof_repository
            .get_proof(
                id,
                &ProofRelations {
                    schema: Some(ProofSchemaRelations {
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    state: Some(ProofStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    verifier_did: Some(DidRelations::default()),
                    receiver_did: Some(DidRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;
        result.try_into()
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
        let now = OffsetDateTime::now_utc();
        let proof_schema = self
            .proof_schema_repository
            .get_proof_schema(&request.proof_schema_id, &ProofSchemaRelations::default())
            .await?;

        let verifier_did = self
            .did_repository
            .get_did(&request.verifier_did_id, &DidRelations::default())
            .await?;

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
    pub async fn share_proof(
        &self,
        id: &ProofId,
        base_url: &str,
    ) -> Result<ShareProofResponseDTO, ServiceError> {
        let (proof, proof_state) = self
            .get_proof_with_state(id, ProofRelations::default())
            .await?;
        match proof_state {
            ProofStateEnum::Created => {
                let now = OffsetDateTime::now_utc();
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
            _ => {
                return Err(ServiceError::AlreadyExists);
            }
        }

        Ok(ShareProofResponseDTO {
            url: format!(
                "{}/ssi/temporary-verifier/v1/connect?protocol={}&proof={}",
                base_url, proof.transport, id
            ),
        })
    }

    /// Mark as offered
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    pub async fn set_holder_connected(
        &self,
        id: &ProofId,
        holder_did_value: &String,
    ) -> Result<(), ServiceError> {
        let (proof, proof_state) = self
            .get_proof_with_state(
                id,
                ProofRelations {
                    verifier_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;
        if proof_state != ProofStateEnum::Pending {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();

        let holder_did = match self
            .did_repository
            .get_did_by_value(holder_did_value, &DidRelations::default())
            .await
        {
            Ok(did) => did,
            Err(DataLayerError::RecordNotFound) => {
                let organisation_id = proof
                    .verifier_did
                    .ok_or(ServiceError::NotFound)?
                    .organisation_id;
                let did = Did {
                    id: Uuid::new_v4(),
                    created_date: now,
                    last_modified: now,
                    name: "prover".to_string(),
                    organisation_id,
                    did: holder_did_value.to_owned(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                };
                self.did_repository.create_did(did.clone()).await?;
                did
            }
            Err(e) => {
                return Err(ServiceError::from(e));
            }
        };

        self.proof_repository
            .set_proof_receiver_did(id, holder_did)
            .await?;

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
    pub async fn accept_proof(
        &self,
        id: &ProofId,
        proved_claims: Vec<CreateProofClaimRequestDTO>,
    ) -> Result<(), ServiceError> {
        let (_, proof_state) = self
            .get_proof_with_state(id, ProofRelations::default())
            .await?;
        if proof_state != ProofStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

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

    /// Proof rejected by user
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    pub async fn reject_proof(&self, id: &ProofId) -> Result<(), ServiceError> {
        let (_, proof_state) = self
            .get_proof_with_state(id, ProofRelations::default())
            .await?;
        if proof_state != ProofStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Rejected,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    /// Proof submit failed or another error occured
    ///
    /// # Arguments
    ///
    /// * `id` - proof identifier
    pub async fn fail_proof(&self, id: &ProofId) -> Result<(), ServiceError> {
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

    // ============ Private methods

    /// Get latest proof state
    async fn get_proof_with_state(
        &self,
        id: &ProofId,
        relations: ProofRelations,
    ) -> Result<(Proof, ProofStateEnum), ServiceError> {
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

        let proof_states = proof.state.as_ref().ok_or(ServiceError::NotFound)?;
        let latest_state = proof_states
            .get(0)
            .ok_or(ServiceError::NotFound)?
            .state
            .to_owned();
        Ok((proof, latest_state))
    }
}
