use super::{
    dto::InvitationResponseDTO,
    mapper::{
        interaction_from_handle_invitation, parse_query, proof_from_handle_invitation,
        remote_did_from_value, string_to_uuid,
    },
    SSIHolderService,
};
use crate::{
    common_mapper::get_base_url,
    model::{
        claim::{Claim, ClaimId},
        credential::{
            Credential, CredentialId, CredentialRelations, CredentialState, CredentialStateEnum,
            CredentialStateRelations, UpdateCredentialRequest,
        },
        credential_schema::CredentialSchema,
        did::{Did, DidRelations},
        interaction::{InteractionId, InteractionRelations},
        organisation::{OrganisationId, OrganisationRelations},
    },
    repository::error::DataLayerError,
    service::{
        credential::dto::CredentialResponseDTO, did::dto::DidId, error::ServiceError,
        proof::dto::ProofId,
    },
    transport_protocol::dto::{ConnectVerifierResponse, InvitationResponse},
};

use time::OffsetDateTime;
use uuid::Uuid;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: &str,
        holder_did_id: &DidId,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let url_query_params = parse_query(url)?;

        let base_url = get_base_url(url)?;

        let holder_did = self
            .did_repository
            .get_did(holder_did_id, &DidRelations::default())
            .await?;

        let connect_response = self
            .protocol_provider
            .get_protocol(&url_query_params.protocol)?
            .handle_invitation(url, &holder_did.did)
            .await?;

        match connect_response {
            InvitationResponse::Proof {
                proof_id,
                proof_request,
            } => {
                self.handle_proof_invitation(
                    base_url,
                    proof_id,
                    proof_request,
                    &url_query_params.protocol,
                    &holder_did.organisation_id,
                )
                .await
            }
            InvitationResponse::Credential(issuer_response) => {
                self.handle_credential_invitation(base_url, holder_did, *issuer_response)
                    .await
            }
        }
    }

    pub async fn reject_proof_request(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &ProofId,
    ) -> Result<(), ServiceError> {
        self.protocol_provider
            .get_protocol(transport_protocol)?
            .reject_proof(base_url, &proof_id.to_string())
            .await
            .map_err(ServiceError::from)
    }

    pub async fn submit_proof(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &ProofId,
        credential_ids: &[CredentialId],
        holder_did_id: &DidId,
    ) -> Result<(), ServiceError> {
        let holder_did = self
            .did_repository
            .get_did(holder_did_id, &DidRelations::default())
            .await?;

        let mut credentials: Vec<String> = vec![];
        for credential_id in credential_ids {
            let credential_data = self
                .credential_repository
                .get_credential(credential_id, &CredentialRelations::default())
                .await?
                .credential;

            if credential_data.is_empty() {
                return Err(ServiceError::NotFound);
            }
            let credential_content = std::str::from_utf8(&credential_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;

            credentials.push(credential_content.to_owned());
        }

        // FIXME - pick correct formatter
        let formatter = self.formatter_provider.get_formatter("JWT")?;
        let presentation = formatter.format_presentation(&credentials, &holder_did.did)?;

        self.protocol_provider
            .get_protocol(transport_protocol)?
            .submit_proof(base_url, &proof_id.to_string(), &presentation)
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
            let latest_state = credential
                .state
                .as_ref()
                .ok_or(ServiceError::MappingError("state is None".to_string()))?
                .get(0)
                .ok_or(ServiceError::MappingError("state is missing".to_string()))?;

            if latest_state.state != CredentialStateEnum::Pending {
                return Err(ServiceError::AlreadyExists);
            }

            let interaction = credential
                .interaction
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "interaction is None".to_string(),
                ))?;

            let base_url = interaction
                .host
                .as_ref()
                .ok_or(ServiceError::MappingError("host is None".to_string()))?;

            let credential_content = self
                .protocol_provider
                .get_protocol(&credential.transport)?
                .accept_credential(base_url, &credential.id.to_string())
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
            let latest_state = credential
                .state
                .as_ref()
                .ok_or(ServiceError::MappingError("state is None".to_string()))?
                .get(0)
                .ok_or(ServiceError::MappingError("state is missing".to_string()))?;

            if latest_state.state != CredentialStateEnum::Pending {
                return Err(ServiceError::AlreadyExists);
            }

            let interaction = credential
                .interaction
                .as_ref()
                .ok_or(ServiceError::MappingError(
                    "interaction is None".to_string(),
                ))?;

            let base_url = interaction
                .host
                .as_ref()
                .ok_or(ServiceError::MappingError("host is None".to_string()))?;

            self.protocol_provider
                .get_protocol(&credential.transport)?
                .reject_credential(base_url, &credential.id.to_string())
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

    // ====== private methods
    async fn handle_proof_invitation(
        &self,
        base_url: String,
        proof_id: String,
        proof_request: ConnectVerifierResponse,
        protocol: &str,
        organisation_id: &OrganisationId,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let verifier_did_result = self
            .did_repository
            .get_did_by_value(&proof_request.verifier_did, &DidRelations::default())
            .await;

        let now = OffsetDateTime::now_utc();
        let verifier_did = match verifier_did_result {
            Ok(did) => did,
            Err(DataLayerError::RecordNotFound) => {
                let new_did = Did {
                    id: Uuid::new_v4(),
                    created_date: now,
                    last_modified: now,
                    name: "verifier".to_owned(),
                    organisation_id: organisation_id.to_owned(),
                    did: proof_request.verifier_did.clone(),
                    did_type: crate::model::did::DidType::Remote,
                    did_method: "KEY".to_owned(),
                };
                self.did_repository.create_did(new_did.clone()).await?;
                new_did
            }
            Err(e) => return Err(ServiceError::GeneralRuntimeError(e.to_string())),
        };

        let data = serde_json::to_string(&proof_request.claims)
            .unwrap()
            .as_bytes()
            .to_vec();

        let interaction = interaction_from_handle_invitation(base_url, Some(data), now);

        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await?;

        let proof = proof_from_handle_invitation(protocol, verifier_did, interaction, now);

        self.proof_repository.create_proof(proof).await?;

        Ok(InvitationResponseDTO::ProofRequest {
            interaction_id,
            proof_id: string_to_uuid(&proof_id)?,
            proof_request: proof_request.try_into()?,
        })
    }

    async fn handle_credential_invitation(
        &self,
        base_url: String,
        holder_did: Did,
        issuer_response: CredentialResponseDTO,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let organisation_id = holder_did.organisation_id;
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &OrganisationRelations::default())
            .await?;

        let mut credential_schema: CredentialSchema = issuer_response.schema.into();
        credential_schema.organisation = Some(organisation);
        credential_schema.claim_schemas = Some(
            issuer_response
                .claims
                .iter()
                .map(|claim| claim.schema.to_owned().into())
                .collect(),
        );

        let result = self
            .credential_schema_repository
            .create_credential_schema(credential_schema.clone())
            .await;
        if let Err(error) = result {
            if error != DataLayerError::AlreadyExists {
                return Err(ServiceError::from(error));
            }
        }

        // insert issuer did if not yet known
        let issuer_did_value = issuer_response
            .issuer_did
            .ok_or(ServiceError::IncorrectParameters)?;
        let issuer_did = remote_did_from_value(issuer_did_value.to_owned(), organisation_id);
        let did_insert_result = self.did_repository.create_did(issuer_did.clone()).await;
        let issuer_did = match did_insert_result {
            Ok(_) => issuer_did,
            Err(DataLayerError::AlreadyExists) => {
                self.did_repository
                    .get_did_by_value(&issuer_did_value, &DidRelations::default())
                    .await?
            }
            Err(e) => return Err(ServiceError::from(e)),
        };

        let now = OffsetDateTime::now_utc();

        let interaction = interaction_from_handle_invitation(base_url, None, now);
        let interaction_id = self
            .interaction_repository
            .create_interaction(interaction.clone())
            .await?;

        // create credential
        let incoming_claims = issuer_response.claims;
        let claims = credential_schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "claim_schemas is None".to_string(),
            ))?
            .iter()
            .map(|claim_schema| -> Result<Option<Claim>, ServiceError> {
                if let Some(value) = incoming_claims
                    .iter()
                    .find(|claim| claim.schema.key == claim_schema.schema.key)
                {
                    Ok(Some(Claim {
                        schema: Some(claim_schema.schema.to_owned()),
                        value: value.value.to_owned(),
                        id: ClaimId::new_v4(),
                        created_date: now,
                        last_modified: now,
                    }))
                } else if claim_schema.required {
                    Err(ServiceError::ValidationError(format!(
                        "Claim key {} missing",
                        &claim_schema.schema.key
                    )))
                } else {
                    Ok(None) // missing optional claim
                }
            })
            .collect::<Result<Vec<Option<Claim>>, ServiceError>>()?
            .into_iter()
            .flatten()
            .collect();

        self.credential_repository
            .create_credential(Credential {
                id: issuer_response.id,
                created_date: now,
                issuance_date: now,
                last_modified: now,
                credential: vec![],
                transport: "PROCIVIS_TEMPORARY".to_string(),
                state: Some(vec![CredentialState {
                    created_date: now,
                    state: CredentialStateEnum::Pending,
                }]),
                claims: Some(claims),
                issuer_did: Some(issuer_did),
                holder_did: Some(holder_did),
                schema: Some(credential_schema),
                interaction: Some(interaction),
            })
            .await?;

        Ok(InvitationResponseDTO::Credential {
            credential_id: issuer_response.id,
            interaction_id,
        })
    }
}
