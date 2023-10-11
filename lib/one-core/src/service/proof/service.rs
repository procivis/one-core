use super::{
    dto::{
        CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO,
        PresentationDefinitionResponseDTO, ProofDetailResponseDTO, ProofId,
    },
    mapper::{get_holder_proof_detail, get_verifier_proof_detail, proof_from_create_request},
    ProofService,
};
use crate::model::credential::{CredentialRelations, CredentialStateRelations};
use crate::service::proof::mapper::{
    get_proof_claim_schemas_from_proof, presentation_definition_from_proof,
};
use crate::service::proof::validator::{check_holder_did_is_local, check_last_proof_state};
use crate::{
    common_mapper::list_response_try_into,
    model::{
        claim::ClaimRelations,
        claim_schema::ClaimSchemaRelations,
        common::EntityShareResponseDTO,
        credential_schema::CredentialSchemaRelations,
        did::DidRelations,
        interaction::InteractionRelations,
        organisation::OrganisationRelations,
        proof::{Proof, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
        proof_schema::{ProofSchemaClaimRelations, ProofSchemaRelations},
    },
    service::error::ServiceError,
};
use time::OffsetDateTime;

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
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    interaction: Some(InteractionRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;

        if result.schema.is_some() {
            get_verifier_proof_detail(result)
        } else {
            get_holder_proof_detail(result)
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
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                },
            )
            .await
            .map_err(ServiceError::from)?;

        check_holder_did_is_local(&proof)?;
        check_last_proof_state(&proof, ProofStateEnum::Pending)?;

        let claims = get_proof_claim_schemas_from_proof(&proof)?;
        let claim_names: Vec<String> = claims
            .iter()
            .map(|claim_schema| claim_schema.clone().key)
            .collect();

        let credentials = self
            .credential_repository
            .get_credentials_by_claim_names(
                claim_names.clone(),
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        let credentials: Vec<_> = credentials
            .into_iter()
            .filter(|credential| {
                claim_names.clone().into_iter().all(|claim_name| {
                    if let Some(claims) = &credential.claims {
                        claims.iter().any(|claim| {
                            if let Some(claim_schema) = &claim.schema {
                                claim_name == claim_schema.key
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                })
            })
            .collect();

        presentation_definition_from_proof(proof, credentials, claims)
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

        // ONE-843: cannot create proof based on deleted schema
        if proof_schema.deleted_at.is_some() {
            return Err(ServiceError::NotFound);
        }

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
    pub async fn share_proof(&self, id: &ProofId) -> Result<EntityShareResponseDTO, ServiceError> {
        let (proof, proof_state) = self.get_proof_with_state(id).await?;
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

        Ok(EntityShareResponseDTO {
            id: id.to_owned(),
            transport: proof.transport,
        })
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
