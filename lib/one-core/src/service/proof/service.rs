use super::{
    dto::{
        CreateProofRequestDTO, GetProofListResponseDTO, GetProofQueryDTO,
        PresentationDefinitionResponseDTO, ProofDetailResponseDTO, ProofId,
    },
    mapper::{get_holder_proof_detail, get_verifier_proof_detail, proof_from_create_request},
    model::CredentialGroup,
    ProofService,
};
use crate::model::credential::{CredentialRelations, CredentialStateRelations};
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
use crate::{
    model::credential::CredentialId,
    service::proof::mapper::{
        get_proof_claim_schemas_from_proof, presentation_definition_from_proof,
    },
};
use std::collections::{HashMap, HashSet};
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
                    state: Some(ProofStateRelations::default()),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(ServiceError::from)?;

        check_holder_did_is_local(&proof)?;
        check_last_proof_state(&proof, ProofStateEnum::Pending)?;

        let requested_claims = get_proof_claim_schemas_from_proof(&proof)?;
        let requested_claim_keys: Vec<String> = requested_claims
            .iter()
            .map(|claim_schema| claim_schema.key.to_owned())
            .collect();

        let mut credential_groups: HashMap<String, CredentialGroup> = HashMap::new();
        for requested_claim in requested_claims {
            let group_id = &requested_claim.credential_schema.id;
            if let Some(group) = credential_groups.get_mut(group_id) {
                group.claims.push(requested_claim);
            } else {
                credential_groups.insert(
                    group_id.to_owned(),
                    CredentialGroup {
                        claims: vec![requested_claim],
                        ..Default::default()
                    },
                );
            }
        }

        let relevant_credentials = self
            .credential_repository
            .get_credentials_by_claim_names(
                requested_claim_keys.clone(),
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
            .await?;

        let mut mentioned_credential_ids: HashSet<CredentialId> = HashSet::new();
        for group in credential_groups.values_mut() {
            for credential in &relevant_credentials {
                let claim_schemas = credential
                    .claims
                    .as_ref()
                    .ok_or(ServiceError::MappingError("claims missing".to_string()))?
                    .iter()
                    .map(|claim| {
                        claim
                            .schema
                            .as_ref()
                            .ok_or(ServiceError::MappingError("schema missing".to_string()))
                    })
                    .collect::<Result<Vec<_>, _>>()?;

                if group.claims.iter().all(|requested_claim| {
                    claim_schemas
                        .iter()
                        .any(|claim_schema| requested_claim.key == claim_schema.key)
                }) {
                    group.applicable_credentials.push(credential.to_owned());
                    mentioned_credential_ids.insert(credential.id);
                }
            }
        }

        let used_credentials = relevant_credentials
            .into_iter()
            .filter(|credential| mentioned_credential_ids.contains(&credential.id))
            .collect();

        presentation_definition_from_proof(proof, used_credentials, credential_groups)
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
            _ => {
                return Err(ServiceError::AlreadyShared);
            }
        }

        let transport_instance = &self
            .config
            .exchange
            .get(&proof.transport)
            .ok_or(ServiceError::MissingTransportProtocol(
                proof.transport.to_owned(),
            ))?
            .r#type;

        let transport = self.protocol_provider.get_protocol(transport_instance)?;

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
