use super::{
    dto::{InvitationResponseDTO, PresentationSubmitRequestDTO},
    mapper::{
        credential_accepted_history_event, credential_offered_history_event,
        credential_pending_history_event, credential_rejected_history_event,
        proof_accepted_history_event, proof_pending_history_event, proof_rejected_history_event,
        proof_requested_history_event,
    },
    SSIHolderService,
};

use crate::{
    common_validator::{
        throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
    },
    config::core_config::{Fields, RevocationType},
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential::{
            CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
            UpdateCredentialRequest,
        },
        credential_schema::{CredentialSchemaRelations, WalletStorageTypeEnum},
        did::{DidRelations, KeyRole},
        interaction::{InteractionId, InteractionRelations},
        key::KeyRelations,
        organisation::OrganisationRelations,
        proof::{ProofRelations, ProofState, ProofStateEnum, ProofStateRelations},
    },
    provider::{
        credential_formatter::model::CredentialPresentation,
        key_storage::KeySecurity,
        revocation::lvvc::prepare_bearer_token,
        transport_protocol::{
            dto::{PresentationDefinitionRequestedCredentialResponseDTO, PresentedCredential},
            provider::DetectedProtocol,
            TransportProtocolError,
        },
    },
    service::{
        error::{
            BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError,
            ValidationError,
        },
        ssi_issuer::dto::IssuerResponseDTO,
        ssi_validator::validate_config_entity_presence,
    },
    util::oidc::detect_correct_format,
};
use shared_types::{DidId, KeyId};
use time::OffsetDateTime;
use url::Url;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        holder_did_id: &DidId,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        validate_config_entity_presence(&self.config)?;

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

        let Some(holder_did) = holder_did else {
            return Err(EntityNotFoundError::Did(*holder_did_id).into());
        };

        let DetectedProtocol { protocol, .. } = self
            .protocol_provider
            .detect_protocol(&url)
            .ok_or(ServiceError::MissingTransportProtocol(
                "Cannot detect transport protocol".to_string(),
            ))?;

        let response = protocol.handle_invitation(url, holder_did).await?;
        match &response {
            InvitationResponseDTO::Credential { credentials, .. } => {
                for credential in credentials.iter() {
                    let _ = self
                        .history_repository
                        .create_history(credential_offered_history_event(credential))
                        .await;

                    self.credential_repository
                        .create_credential(credential.to_owned())
                        .await?;

                    let _ = self
                        .history_repository
                        .create_history(credential_pending_history_event(credential))
                        .await;
                }
            }
            InvitationResponseDTO::ProofRequest { proof, .. } => {
                let _ = self
                    .history_repository
                    .create_history(proof_requested_history_event(proof))
                    .await;

                self.proof_repository
                    .create_proof(*proof.to_owned())
                    .await?;

                let _ = self
                    .history_repository
                    .create_history(proof_pending_history_event(proof))
                    .await;
            }
        }

        Ok(response)
    }

    pub async fn reject_proof_request(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(
                interaction_id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let Some(proof) = proof else {
            return Err(BusinessLogicError::MissingProofForInteraction(*interaction_id).into());
        };

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        self.protocol_provider
            .get_protocol(&proof.transport)
            .ok_or(MissingProviderError::TransportProtocol(
                proof.transport.clone(),
            ))?
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
            .await?;

        let _ = self
            .history_repository
            .create_history(proof_rejected_history_event(&proof))
            .await;

        Ok(())
    }

    pub async fn submit_proof(
        &self,
        submission: PresentationSubmitRequestDTO,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let Some(proof) = self
            .proof_repository
            .get_proof_by_interaction_id(
                &submission.interaction_id,
                &ProofRelations {
                    state: Some(ProofStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(
                BusinessLogicError::MissingProofForInteraction(submission.interaction_id).into(),
            );
        };

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?;

        let Some(did) = self
            .did_repository
            .get_did(
                &submission.did_id,
                &DidRelations {
                    keys: Some(Default::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(ValidationError::DidNotFound.into());
        };

        match submission.key_id {
            Some(key_id) => did.find_key(&key_id, KeyRole::Authentication)?,
            None => did.find_key_by_role(KeyRole::Authentication)?,
        };

        let transport_protocol = self
            .protocol_provider
            .get_protocol(&proof.transport)
            .ok_or(MissingProviderError::TransportProtocol(
                proof.transport.clone(),
            ))?;
        let presentation_definition = transport_protocol
            .get_presentation_definition(&proof)
            .await?;

        let requested_credentials: Vec<PresentationDefinitionRequestedCredentialResponseDTO> =
            presentation_definition
                .request_groups
                .into_iter()
                .flat_map(|group| group.requested_credentials)
                .collect();

        let mut submitted_claims: Vec<Claim> = vec![];
        let mut credential_presentations: Vec<PresentedCredential> = vec![];

        for (requested_credential_id, credential_request) in submission.submit_credentials {
            let requested_credential = requested_credentials
                .iter()
                .find(|credential| credential.id == requested_credential_id)
                .ok_or(ServiceError::MappingError(format!(
                    "requested credential `{requested_credential_id}` not found"
                )))?;

            let submitted_keys = requested_credential
                .fields
                .iter()
                .filter(|field| credential_request.submit_claims.contains(&field.id))
                .map(|field| {
                    Ok(field
                        .key_map
                        .get(&credential_request.credential_id.to_string())
                        .ok_or(ServiceError::MappingError(format!(
                            "no matching key for credential_id `{}`",
                            credential_request.credential_id
                        )))?
                        .to_owned())
                })
                .collect::<Result<Vec<String>, ServiceError>>()?;

            let Some(credential) = self
                .credential_repository
                .get_credential(
                    &credential_request.credential_id,
                    &CredentialRelations {
                        claims: Some(ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        }),
                        holder_did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        issuer_did: Some(DidRelations::default()),
                        schema: Some(CredentialSchemaRelations::default()),
                        ..Default::default()
                    },
                )
                .await?
            else {
                return Err(
                    EntityNotFoundError::Credential(credential_request.credential_id).into(),
                );
            };

            let credential_data = credential.credential.as_slice();
            if credential_data.is_empty() {
                return Err(BusinessLogicError::MissingCredentialData {
                    credential_id: credential_request.credential_id,
                }
                .into());
            }
            let credential_content = std::str::from_utf8(credential_data)
                .map_err(|e| ServiceError::MappingError(e.to_string()))?;

            let credential_schema =
                credential
                    .schema
                    .as_ref()
                    .ok_or(ServiceError::MappingError(
                        "credential_schema missing".to_string(),
                    ))?;

            for claim in credential
                .claims
                .as_ref()
                .ok_or(ServiceError::MappingError("claims missing".to_string()))?
            {
                let claim_schema = claim.schema.as_ref().ok_or(ServiceError::MappingError(
                    "claim_schema missing".to_string(),
                ))?;

                if submitted_keys.contains(&claim_schema.key)
                    && submitted_claims.iter().all(|c| c.id != claim.id)
                {
                    submitted_claims.push(claim.to_owned());
                }
            }

            // Workaround credential format detection
            let format = detect_correct_format(credential_schema, credential_content)?;

            let formatter = self
                .formatter_provider
                .get_formatter(&format)
                .ok_or(MissingProviderError::Formatter(format.to_string()))?;

            let credential_presentation = CredentialPresentation {
                token: credential_content.to_owned(),
                disclosed_keys: submitted_keys.to_owned(),
            };

            let formatted_credential_presentation = formatter
                .format_credential_presentation(credential_presentation)
                .await?;

            credential_presentations.push(PresentedCredential {
                presentation: formatted_credential_presentation.to_owned(),
                credential_schema: credential_schema.to_owned(),
                request: requested_credential.to_owned(),
            });

            let revocation_method: Fields<RevocationType> = self
                .config
                .revocation
                .get(&credential_schema.revocation_method)?;
            if revocation_method.r#type == RevocationType::Lvvc {
                let extracted = formatter
                    .extract_credentials_unverified(&formatted_credential_presentation)
                    .await?;
                let credential_status = extracted
                    .status
                    .first()
                    .ok_or(ServiceError::MappingError(
                        "credential_status is None".to_string(),
                    ))?
                    .to_owned();

                let bearer_token =
                    prepare_bearer_token(&credential, self.key_provider.clone()).await?;

                let lvvc_url = credential_status.id;

                let client = reqwest::Client::new();
                let response: IssuerResponseDTO = client
                    .get(lvvc_url)
                    .bearer_auth(bearer_token)
                    .send()
                    .await
                    .map_err(TransportProtocolError::HttpRequestError)?
                    .error_for_status()
                    .map_err(TransportProtocolError::HttpRequestError)?
                    .json()
                    .await
                    .map_err(TransportProtocolError::HttpRequestError)?;

                let lvvc_content = response.credential;
                let lvvc_presentation = CredentialPresentation {
                    token: lvvc_content.to_owned(),
                    disclosed_keys: vec!["id".to_string(), "status".to_string()],
                };

                let formatted_lvvc_presentation = formatter
                    .format_credential_presentation(lvvc_presentation)
                    .await?;

                credential_presentations.push(PresentedCredential {
                    presentation: formatted_lvvc_presentation,
                    credential_schema: credential_schema.to_owned(),
                    request: requested_credential.to_owned(),
                });
            }
        }

        let submit_result = transport_protocol
            .submit_proof(&proof, credential_presentations)
            .await;

        if submit_result.is_ok() {
            self.proof_repository
                .set_proof_holder_did(&proof.id, did)
                .await?;

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
            .await?;

        if submit_result.is_ok() {
            let _ = self
                .history_repository
                .create_history(proof_accepted_history_event(&proof))
                .await;
        }

        Ok(submit_result?)
    }

    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
        did_id: DidId,
        key_id: Option<KeyId>,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    holder_did: Some(DidRelations {
                        keys: Some(KeyRelations::default()),
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    issuer_did: Some(DidRelations::default()),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(BusinessLogicError::MissingCredentialsForInteraction {
                interaction_id: *interaction_id,
            }
            .into());
        }

        let Some(did) = self
            .did_repository
            .get_did(
                &did_id,
                &DidRelations {
                    keys: Some(Default::default()),
                    organisation: None,
                },
            )
            .await?
        else {
            return Err(ValidationError::DidNotFound.into());
        };

        let selected_key = match key_id {
            Some(key_id) => did.find_key(&key_id, KeyRole::Authentication)?,
            None => did.find_key_by_role(KeyRole::Authentication)?,
        };

        let key_security = self
            .key_provider
            .get_key_storage(&selected_key.storage_type)
            .ok_or_else(|| MissingProviderError::KeyStorage(selected_key.storage_type.clone()))?
            .get_capabilities()
            .security;

        for credential in credentials {
            throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

            let wallet_storage_matches = match credential
                .schema
                .as_ref()
                .and_then(|schema| schema.wallet_storage_type.as_ref())
            {
                Some(WalletStorageTypeEnum::Hardware) => {
                    key_security.contains(&KeySecurity::Hardware)
                }
                Some(WalletStorageTypeEnum::Software) => {
                    key_security.contains(&KeySecurity::Software)
                }
                None => true,
            };

            if !wallet_storage_matches {
                return Err(BusinessLogicError::UnfulfilledWalletStorageType.into());
            }

            let issuer_response = self
                .protocol_provider
                .get_protocol(&credential.transport)
                .ok_or(MissingProviderError::TransportProtocol(
                    credential.transport.clone(),
                ))?
                .accept_credential(&credential, &did_id, &Some(selected_key.id))
                .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Accepted,
                        suspend_end_date: None,
                    }),
                    credential: Some(issuer_response.credential.bytes().collect()),
                    holder_did_id: Some(did_id),
                    issuer_did_id: None,
                    interaction: None,
                    key: Some(selected_key.id),
                    redirect_uri: None,
                })
                .await?;

            let _ = self
                .history_repository
                .create_history(credential_accepted_history_event(&credential))
                .await;
        }

        Ok(())
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), ServiceError> {
        validate_config_entity_presence(&self.config)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )
            .await?;

        if credentials.is_empty() {
            return Err(BusinessLogicError::MissingCredentialsForInteraction {
                interaction_id: *interaction_id,
            }
            .into());
        }

        for credential in credentials {
            throw_if_latest_credential_state_not_eq(&credential, CredentialStateEnum::Pending)?;

            self.protocol_provider
                .get_protocol(&credential.transport)
                .ok_or(MissingProviderError::TransportProtocol(
                    credential.transport.clone(),
                ))?
                .reject_credential(&credential)
                .await?;

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: OffsetDateTime::now_utc(),
                        state: CredentialStateEnum::Rejected,
                        suspend_end_date: None,
                    }),
                    credential: None,
                    holder_did_id: None,
                    issuer_did_id: None,
                    interaction: None,
                    key: None,
                    redirect_uri: None,
                })
                .await?;

            let _ = self
                .history_repository
                .create_history(credential_rejected_history_event(&credential))
                .await;
        }

        Ok(())
    }
}
