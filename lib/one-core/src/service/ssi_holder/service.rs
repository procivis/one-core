use super::{
    dto::{InvitationResponseDTO, PresentationSubmitRequestDTO},
    SSIHolderService,
};
use crate::{
    common_mapper::get_algorithm_from_key_algorithm,
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential::{
            CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::CredentialSchemaRelations,
        did::{DidRelations, KeyRole},
        interaction::{InteractionId, InteractionRelations},
        key::KeyRelations,
        organisation::OrganisationRelations,
        proof::{ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
    },
    provider::credential_formatter::model::PresentationCredential,
    service::{did::dto::DidId, error::ServiceError},
};
use crate::{
    common_validator::throw_if_latest_credential_state_not_eq,
    provider::transport_protocol::provider::DetectedProtocol,
};
use time::OffsetDateTime;
use url::Url;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        holder_did_id: &DidId,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let holder_did = self
            .did_repository
            .get_did(
                holder_did_id,
                &DidRelations {
                    organisation: Some(OrganisationRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let DetectedProtocol { protocol, .. } = self
            .protocol_provider
            .detect_protocol(&url)
            .ok_or(ServiceError::MissingTransportProtocol(
                "Cannot detect transport protocol".to_string(),
            ))?;

        Ok(protocol.handle_invitation(url, holder_did).await?)
    }

    pub async fn reject_proof_request(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                interaction_id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = proof
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .to_owned();

        if latest_state.state != ProofStateEnum::Pending {
            return Err(ServiceError::AlreadyExists);
        }

        self.protocol_provider
            .get_protocol(&proof.transport)?
            .reject_proof(&proof)
            .await?;

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: ProofStateEnum::Rejected,
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn submit_proof(
        &self,
        request: PresentationSubmitRequestDTO,
    ) -> Result<(), ServiceError> {
        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                &request.interaction_id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let latest_state = proof
            .state
            .as_ref()
            .ok_or(ServiceError::MappingError("state is None".to_string()))?
            .get(0)
            .ok_or(ServiceError::MappingError("state is missing".to_string()))?
            .to_owned();

        if latest_state.state != ProofStateEnum::Pending {
            return Err(ServiceError::AlreadyExists);
        }

        let holder_did = proof
            .holder_did
            .as_ref()
            .ok_or(ServiceError::MappingError("holder_did is None".to_string()))?;

        let mut submitted_claims: Vec<Claim> = vec![];
        let mut credentials: Vec<PresentationCredential> = vec![];

        // This is a temporary format selection. Will change in the future.
        let mut format = String::from("JWT"); // Default
        for (_, credential_request) in request.submit_credentials {
            let credential = self
                .credential_repository
                .get_credential(
                    &credential_request.credential_id,
                    &CredentialRelations {
                        claims: Some(ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        }),
                        schema: Some(CredentialSchemaRelations::default()),
                        ..Default::default()
                    },
                )
                .await?;

            let credential_data = credential.credential;
            if credential_data.is_empty() {
                return Err(ServiceError::NotFound);
            }
            let credential_content = std::str::from_utf8(&credential_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;

            if let Some(schema) = &credential.schema {
                format = schema.format.clone();
            }

            let requested_claims: Vec<(Claim, ClaimSchema)> = credential
                .claims
                .as_ref()
                .map(|claims| {
                    claims
                        .iter()
                        .filter_map(|claim| {
                            claim
                                .schema
                                .as_ref()
                                .map(|claim_schema| (claim.clone(), claim_schema.clone()))
                        })
                        .filter(|(_, schema)| {
                            credential_request
                                .submit_claims
                                .contains(&schema.id.to_string())
                        })
                        .collect()
                })
                .unwrap_or_default();

            let (claims, claim_schemas): (Vec<Claim>, Vec<ClaimSchema>) =
                requested_claims.into_iter().unzip();

            credentials.push(PresentationCredential {
                token: credential_content.to_owned(),
                disclosed_keys: claim_schemas
                    .into_iter()
                    .map(|claim_schema| claim_schema.key)
                    .collect(),
            });

            submitted_claims.extend(claims);
        }

        let formatter = self.formatter_provider.get_formatter(&format)?;

        let keys = holder_did
            .keys
            .as_ref()
            .ok_or(ServiceError::MappingError("Holder has no keys".to_string()))?;

        let key = keys
            .iter()
            .find(|k| k.role == KeyRole::AssertionMethod)
            .ok_or(ServiceError::Other("Missing Key".to_owned()))?;

        let algorithm = get_algorithm_from_key_algorithm(&key.key.key_type, &self.config)?;

        let signer = self
            .crypto
            .signers
            .get(&algorithm)
            .ok_or(ServiceError::MissingSigner(algorithm.clone()))?
            .clone();

        let key_provider = self.key_provider.get_key_storage(&key.key.storage_type)?;

        let private_key_moved = key_provider.decrypt_private_key(&key.key.private_key)?;
        let public_key_moved = key.key.public_key.clone();

        let auth_fn = Box::new(move |data: &str| {
            let signer = signer;
            let private_key = private_key_moved;
            let public_key = public_key_moved;
            signer.sign(data, &public_key, &private_key)
        });

        let presentation = formatter.format_presentation(
            &credentials,
            &holder_did.did,
            &key.key.key_type,
            auth_fn,
        )?;

        let submit_result = self
            .protocol_provider
            .get_protocol(&proof.transport)?
            .submit_proof(&proof, &presentation)
            .await;

        if submit_result.is_ok() {
            self.proof_repository
                .set_proof_claims(&proof.id, submitted_claims)
                .await?;
        }

        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state: if submit_result.is_ok() {
                        ProofStateEnum::Accepted
                    } else {
                        ProofStateEnum::Error
                    },
                },
            )
            .await
            .map_err(ServiceError::from)
    }

    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }

        for credential in credentials {
            throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

            let credential_content = self
                .protocol_provider
                .get_protocol(&credential.transport)?
                .accept_credential(&credential)
                .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Accepted,
                    }),
                    credential: Some(credential_content.credential.bytes().collect()),
                    ..Default::default()
                })
                .await?;
        }

        Ok(())
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(ServiceError::NotFound);
        }

        for credential in credentials {
            throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

            self.protocol_provider
                .get_protocol(&credential.transport)?
                .reject_credential(&credential)
                .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Rejected,
                    }),
                    ..Default::default()
                })
                .await?;
        }

        Ok(())
    }
}
