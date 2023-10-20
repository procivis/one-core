use super::{
    dto::{ConnectVerifierResponseDTO, ValidatedProofClaimDTO},
    mapper::proof_verifier_to_connect_verifier_response,
    validator::validate_proof,
    SSIVerifierService,
};
use crate::{
    model::{
        claim::Claim,
        claim_schema::{ClaimSchemaId, ClaimSchemaRelations},
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidRelations, DidType, DidValue},
        organisation::OrganisationRelations,
        proof::{Proof, ProofId, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    repository::error::DataLayerError,
    service::error::ServiceError,
};
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
    ) -> Result<ConnectVerifierResponseDTO, ServiceError> {
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

        let did = proof.verifier_did.ok_or(ServiceError::MappingError(
            "verifier_did is None".to_string(),
        ))?;

        let proof_schema = proof
            .schema
            .ok_or(ServiceError::MappingError("schema is None".to_string()))?;

        let result = proof_verifier_to_connect_verifier_response(proof_schema, did)?;

        self.set_holder_connected(proof_id, holder_did_value)
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
        let (proof, proof_state) = self
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
        if proof_state != ProofStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }
        let proof_schema = proof.schema.ok_or(ServiceError::MappingError(
            "proof schema is None".to_string(),
        ))?;
        let holder_did = proof
            .holder_did
            .ok_or(ServiceError::MappingError("holder did is None".to_string()))?;

        let mut format = "JWT".to_owned(); //Default
        if let Some(claim_schemas) = &proof_schema.claim_schemas {
            if let Some(claim_schema) = &claim_schemas.first() {
                if let Some(credential_schema) = &claim_schema.credential_schema {
                    format = credential_schema.format.to_owned();
                }
            }
        }

        let proved_claims = match validate_proof(
            proof_schema,
            holder_did,
            presentation_content,
            &*self.formatter_provider.get_formatter(&format)?,
        ) {
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
        let (_, proof_state) = self
            .get_proof_with_state(proof_id, ProofRelations::default())
            .await?;
        if proof_state != ProofStateEnum::Offered {
            return Err(ServiceError::AlreadyExists);
        }

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
        holder_did_value: &String,
    ) -> Result<(), ServiceError> {
        let (proof, proof_state) = self
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
                let organisation = proof
                    .verifier_did
                    .ok_or(ServiceError::MappingError(
                        "verifier_did is None".to_string(),
                    ))?
                    .organisation
                    .ok_or(ServiceError::MappingError(
                        "organisation is None".to_string(),
                    ))?;
                let did = Did {
                    id: Uuid::new_v4(),
                    created_date: now,
                    last_modified: now,
                    name: "prover".to_string(),
                    organisation: Some(organisation),
                    did: holder_did_value.to_owned(),
                    did_type: DidType::Remote,
                    did_method: "KEY".to_string(),
                    keys: None,
                };
                self.did_repository.create_did(did.clone()).await?;
                did
            }
            Err(e) => {
                return Err(ServiceError::from(e));
            }
        };

        self.proof_repository
            .set_proof_holder_did(id, holder_did)
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

        let proof_states = proof
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?;
        let latest_state = proof_states
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .state
            .to_owned();
        Ok((proof, latest_state))
    }
}
