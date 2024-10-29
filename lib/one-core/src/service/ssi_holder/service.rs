use std::str::FromStr;

use anyhow::Context;
use futures::TryFutureExt;
use shared_types::{DidId, KeyId, OrganisationId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::PresentationSubmitRequestDTO;
use super::SSIHolderService;
use crate::common_mapper::{encode_cbor_base64, NESTED_CLAIM_MARKER};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::config::core_config::{ExchangeType, Fields, RevocationType};
use crate::config::validator::transport::{
    validate_and_select_transport_type, SelectedTransportType,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchemaRelations, WalletStorageTypeEnum};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::interaction::{InteractionId, InteractionRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{ProofRelations, ProofState, ProofStateEnum, ProofStateRelations};
use crate::model::validity_credential::Mdoc;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCError;
use crate::provider::exchange_protocol::openid4vc::handle_invitation_operations::HandleInvitationOperationsImpl;
use crate::provider::exchange_protocol::openid4vc::mapper::fetch_procivis_schema;
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, PresentedCredential, UpdateResponse,
};
use crate::provider::key_storage::model::KeySecurity;
use crate::provider::revocation::lvvc::prepare_bearer_token;
use crate::service::common_mapper::core_type_to_open_core_type;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::ssi_issuer::dto::IssuerResponseDTO;
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::history::{history_event, log_history_event_credential, log_history_event_proof};
use crate::util::oidc::{
    create_core_to_oicd_format_map, create_core_to_oicd_presentation_format_map,
    create_oicd_to_core_format_map, detect_format_with_crypto_suite, map_core_to_oidc_format,
};

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation_id: OrganisationId,
        transport: Option<Vec<String>>,
        tx_code: Option<String>,
    ) -> Result<InvitationResponseDTO, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(organisation_id))?;

        let protocol = self.protocol_provider.detect_protocol(&url).ok_or(
            ServiceError::MissingExchangeProtocol("Cannot detect exchange protocol".to_string()),
        )?;

        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
        );

        let handle_operations = HandleInvitationOperationsImpl::new(
            organisation.clone(),
            self.credential_schema_repository.clone(),
            self.config.clone(),
        );

        let transport =
            validate_and_select_transport_type(&transport, &self.config.transport, &*protocol)?;
        let transport = match transport {
            SelectedTransportType::Single(s) => s,
            SelectedTransportType::Multiple(vec) => vec
                .into_iter()
                .next()
                .ok_or_else(|| ValidationError::TransportNotAllowedForExchange)?,
        };

        let response = protocol
            .handle_invitation(
                url,
                organisation,
                tx_code,
                &storage_access,
                &handle_operations,
                transport,
            )
            .await?;
        match &response {
            InvitationResponseDTO::Credential { credentials, .. } => {
                for credential in credentials {
                    let _ = self
                        .history_repository
                        .create_history(history_event(
                            credential.id,
                            organisation_id,
                            HistoryEntityType::Credential,
                            HistoryAction::Offered,
                        ))
                        .await;

                    self.credential_repository
                        .create_credential(credential.to_owned())
                        .await?;

                    let _ = self
                        .history_repository
                        .create_history(history_event(
                            credential.id,
                            organisation_id,
                            HistoryEntityType::Credential,
                            HistoryAction::Pending,
                        ))
                        .await;
                }
            }
            InvitationResponseDTO::ProofRequest { proof, .. } => {
                let _ = self
                    .history_repository
                    .create_history(history_event(
                        proof.id,
                        organisation_id,
                        HistoryEntityType::Proof,
                        HistoryAction::Requested,
                    ))
                    .await;

                self.proof_repository
                    .create_proof(*proof.to_owned())
                    .await?;

                let _ = self
                    .history_repository
                    .create_history(history_event(
                        proof.id,
                        organisation_id,
                        HistoryEntityType::Proof,
                        HistoryAction::Pending,
                    ))
                    .await;
            }
        }

        Ok(response)
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

        let exchange = self
            .config
            .exchange
            .get_if_enabled(proof.exchange.as_str())
            .map_err(|_| {
                ServiceError::MissingExchangeProtocol("Exchange not found in config".to_string())
            })?;

        match exchange.r#type {
            ExchangeType::IsoMdl => {
                throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?
            }
            _ => throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Pending)?,
        }

        let state = if (self
            .protocol_provider
            .get_protocol(&proof.exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.exchange.clone(),
            ))?
            .reject_proof(&proof)
            .await)
            .is_ok()
        {
            let _ =
                log_history_event_proof(&*self.history_repository, &proof, HistoryAction::Rejected)
                    .await;
            ProofStateEnum::Rejected
        } else {
            ProofStateEnum::Error
        };
        let now = OffsetDateTime::now_utc();
        self.proof_repository
            .set_proof_state(
                &proof.id,
                ProofState {
                    created_date: now,
                    last_modified: now,
                    state,
                },
            )
            .await?;

        Ok(())
    }

    pub async fn submit_proof(
        &self,
        submission: PresentationSubmitRequestDTO,
    ) -> Result<(), ServiceError> {
        let Some(proof) = self
            .proof_repository
            .get_proof_by_interaction_id(
                &submission.interaction_id,
                &ProofRelations {
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    state: Some(ProofStateRelations::default()),
                    interaction: Some(InteractionRelations::default()),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(
                BusinessLogicError::MissingProofForInteraction(submission.interaction_id).into(),
            );
        };

        let Some(holder_did) = self
            .did_repository
            .get_did(
                &submission.did_id,
                &DidRelations {
                    organisation: Some(Default::default()),
                    keys: Some(Default::default()),
                },
            )
            .await?
        else {
            return Err(ValidationError::DidNotFound.into());
        };

        let selected_key = match submission.key_id {
            Some(key_id) => holder_did.find_key(&key_id, KeyRole::Authentication)?,
            None => holder_did.find_first_key_by_role(KeyRole::Authentication)?,
        };

        let did_document = self.did_method_provider.resolve(&holder_did.did).await?;
        let authentication_methods =
            did_document
                .authentication
                .ok_or(ServiceError::MappingError(
                    "Missing authentication keys".to_owned(),
                ))?;
        let holder_jwk_key_id = match authentication_methods
            .iter()
            .find(|id| id.contains(&selected_key.id.to_string()))
            .cloned()
        {
            Some(id) => id,
            None => authentication_methods
                .first()
                .ok_or(ServiceError::MappingError(
                    "Missing first authentication key".to_owned(),
                ))?
                .to_owned(),
        };

        let exchange_protocol = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            MissingProviderError::ExchangeProtocol(proof.exchange.clone()),
        )?;

        exchange_protocol
            .validate_proof_for_submission(&proof)
            .await?;

        let interaction_data = proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.data.as_ref())
            .map(|interaction| serde_json::from_slice(interaction))
            .ok_or_else(|| ServiceError::MappingError("missing interaction".into()))?
            .map_err(|err| ServiceError::MappingError(err.to_string()))?;

        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
        );

        let presentation_definition = exchange_protocol
            .get_presentation_definition(
                &proof,
                interaction_data,
                &storage_access,
                create_oicd_to_core_format_map(),
                core_type_to_open_core_type(&self.config.datatype),
            )
            .await?;

        let requested_credentials: Vec<_> = presentation_definition
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

            let credential = self
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
                        issuer_did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        schema: Some(CredentialSchemaRelations::default()),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(EntityNotFoundError::Credential(
                    credential_request.credential_id,
                ))?;
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

                for key in &submitted_keys {
                    // handle nested path by checking the prefix
                    if claim_schema
                        .key
                        .starts_with(&format!("{key}{NESTED_CLAIM_MARKER}"))
                        || claim_schema.key == *key
                            && submitted_claims.iter().all(|c| c.id != claim.id)
                    {
                        submitted_claims.push(claim.to_owned());
                    }
                }
            }

            let format =
                detect_format_with_crypto_suite(&credential_schema.format, credential_content)?;

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
                credential_schema: credential_schema.clone(),
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

                let lvvc_url = credential_status.id.ok_or(ServiceError::MappingError(
                    "credential_status id is None".to_string(),
                ))?;

                let response: IssuerResponseDTO = self
                    .client
                    .get(lvvc_url.as_str())
                    .bearer_auth(&bearer_token)
                    .send()
                    .await
                    .context("send error")
                    .map_err(ExchangeProtocolError::Transport)?
                    .error_for_status()
                    .context("status error")
                    .map_err(ExchangeProtocolError::Transport)?
                    .json()
                    .context("parsing error")
                    .map_err(ExchangeProtocolError::Transport)?;

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
                    credential_schema: credential_schema.clone(),
                    request: requested_credential.to_owned(),
                });
            }
        }

        let submit_result = exchange_protocol
            .submit_proof(
                &proof,
                credential_presentations,
                &holder_did,
                selected_key,
                Some(holder_jwk_key_id),
                create_core_to_oicd_format_map(),
                create_core_to_oicd_presentation_format_map(),
            )
            .map_err(ServiceError::from)
            .and_then(|submit_result| async {
                self.resolve_update_response(Some(proof.id), submit_result)
                    .await
            })
            .await;

        self.proof_repository
            .set_proof_holder_did(&proof.id, holder_did.to_owned())
            .await?;

        self.proof_repository
            .set_proof_claims(&proof.id, submitted_claims)
            .await?;

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

        let action = if submit_result.is_ok() {
            HistoryAction::Accepted
        } else {
            HistoryAction::Errored
        };
        let _ = log_history_event_proof(&*self.history_repository, &proof, action).await;

        submit_result
    }

    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
        did_id: DidId,
        key_id: Option<KeyId>,
    ) -> Result<(), ServiceError> {
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
            None => did.find_first_key_by_role(KeyRole::Authentication)?,
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

            let storage_access = StorageProxyImpl::new(
                self.interaction_repository.clone(),
                self.credential_schema_repository.clone(),
                self.credential_repository.clone(),
                self.did_repository.clone(),
            );

            let schema = credential
                .schema
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed("schema is None".to_string()))?;

            let format = if &credential.exchange == "OPENID4VC" {
                map_core_to_oidc_format(&schema.format)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
            } else {
                schema.format.to_owned()
            };

            let mut issuer_response = self
                .protocol_provider
                .get_protocol(&credential.exchange)
                .ok_or(MissingProviderError::ExchangeProtocol(
                    credential.exchange.clone(),
                ))?
                .accept_credential(
                    &credential,
                    &did,
                    selected_key,
                    None,
                    &format,
                    &storage_access,
                    detect_format_with_crypto_suite,
                )
                .await?;

            let layout_missing = issuer_response
                .update_credential_schema
                .as_ref()
                .and_then(|schema| schema.layout_properties.as_ref())
                .is_none();

            // Retry fetching layout if it's not provided via VC
            if layout_missing {
                let url_result = Url::from_str(&schema.schema_id);

                if let Ok(url) = url_result {
                    let result = fetch_procivis_schema(url.as_ref()).await;

                    if let (Ok(response_schema), Some(schema_update_request)) =
                        (result, issuer_response.update_credential_schema.as_mut())
                    {
                        schema_update_request.layout_type = response_schema.layout_type;
                        schema_update_request.layout_properties =
                            response_schema.layout_properties.map(Into::into);
                    }
                }
            }

            let issuer_response = self.resolve_update_response(None, issuer_response).await?;

            let now = OffsetDateTime::now_utc();
            if format == "mso_mdoc" {
                let mso = try_extracting_mso_from_token(&issuer_response.credential).await?;
                let mso_cbor = encode_cbor_base64(mso).map_err(|e| {
                    ServiceError::OpenID4VCError(OpenID4VCError::Other(e.to_string()))
                })?;

                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: now,
                            credential: mso_cbor.into_bytes(),
                            linked_credential_id: credential.id,
                        }
                        .into(),
                    )
                    .await?;
            }

            self.credential_repository
                .update_credential(UpdateCredentialRequest {
                    id: credential.id,
                    state: Some(CredentialState {
                        created_date: now,
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

            let _ = log_history_event_credential(
                &*self.history_repository,
                &credential,
                HistoryAction::Accepted,
            )
            .await;
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
                    holder_did: Some(DidRelations {
                        organisation: Some(OrganisationRelations::default()),
                        ..Default::default()
                    }),
                    schema: Some(CredentialSchemaRelations {
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
                .get_protocol(&credential.exchange)
                .ok_or(MissingProviderError::ExchangeProtocol(
                    credential.exchange.clone(),
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

            let _ = log_history_event_credential(
                &*self.history_repository,
                &credential,
                HistoryAction::Rejected,
            )
            .await;
        }

        Ok(())
    }

    async fn resolve_update_response<T>(
        &self,
        proof_id: Option<ProofId>,
        update_response: UpdateResponse<T>,
    ) -> Result<T, ServiceError> {
        if let Some(update_proof) = update_response.update_proof {
            if let Some(proof_id) = proof_id {
                self.proof_repository
                    .update_proof(&proof_id, update_proof)
                    .await?;
            }
        }
        if let Some(create_did) = update_response.create_did {
            self.did_repository.create_did(create_did).await?;
        }
        if let Some(update_credential_schema) = update_response.update_credential_schema {
            self.credential_schema_repository
                .update_credential_schema(update_credential_schema)
                .await?;
        }
        if let Some(update_credential) = update_response.update_credential {
            self.credential_repository
                .update_credential(update_credential)
                .await?;
        }
        Ok(update_response.result)
    }
}
