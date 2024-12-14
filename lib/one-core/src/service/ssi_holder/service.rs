use futures::TryFutureExt;
use shared_types::{CredentialId, DidId, KeyId, OrganisationId, ProofId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::dto::PresentationSubmitRequestDTO;
use super::SSIHolderService;
use crate::common_mapper::{encode_cbor_base64, value_to_model_claims, NESTED_CLAIM_MARKER};
use crate::common_validator::{
    throw_if_latest_credential_state_not_eq, throw_if_latest_proof_state_not_eq,
};
use crate::config::core_config::{Fields, RevocationType};
use crate::config::validator::transport::{
    validate_and_select_transport_type, SelectedTransportType,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    CredentialRelations, CredentialState, CredentialStateEnum, CredentialStateRelations,
    UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, WalletStorageTypeEnum,
};
use crate::model::did::{DidRelations, KeyRole};
use crate::model::history::{HistoryAction, HistoryEntityType};
use crate::model::interaction::{InteractionId, InteractionRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::OrganisationRelations;
use crate::model::proof::{ProofRelations, ProofStateEnum};
use crate::model::validity_credential::Mdoc;
use crate::provider::credential_formatter::mdoc_formatter::try_extracting_mso_from_token;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::error::OpenID4VCError;
use crate::provider::exchange_protocol::openid4vc::handle_invitation_operations::HandleInvitationOperationsImpl;
use crate::provider::exchange_protocol::openid4vc::model::{
    InvitationResponseDTO, PresentedCredential, UpdateResponse,
};
use crate::provider::key_storage::model::KeySecurity;
use crate::provider::revocation::lvvc::holder_fetch::holder_get_lvvc;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::history::history_event;
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
            self.vct_type_metadata_cache.clone(),
            self.json_schema_cache.clone(),
            self.config.clone(),
            self.client.clone(),
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
            .holder_handle_invitation(
                url,
                organisation,
                &storage_access,
                &handle_operations,
                transport,
            )
            .await?;
        match &response {
            InvitationResponseDTO::Credential { credentials, .. } => {
                for credential in credentials {
                    self.credential_repository
                        .create_credential(credential.to_owned())
                        .await?;
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

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let state = if (self
            .protocol_provider
            .get_protocol(&proof.exchange)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.exchange.clone(),
            ))?
            .holder_reject_proof(&proof)
            .await)
            .is_ok()
        {
            ProofStateEnum::Rejected
        } else {
            ProofStateEnum::Error
        };
        self.proof_repository
            .set_proof_state(&proof.id, state)
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
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
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

        let holder_jwk_key_id = self
            .did_method_provider
            .get_verification_method_id_from_did_and_key(&holder_did, selected_key)
            .await?;

        let exchange_protocol = self.protocol_provider.get_protocol(&proof.exchange).ok_or(
            MissingProviderError::ExchangeProtocol(proof.exchange.clone()),
        )?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

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
            .holder_get_presentation_definition(
                &proof,
                interaction_data,
                &storage_access,
                create_oicd_to_core_format_map(),
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

                let revocation_params = self
                    .config
                    .revocation
                    .get(&credential_schema.revocation_method)?;

                let lvvc = holder_get_lvvc(
                    &credential,
                    &credential_status,
                    &*self.validity_credential_repository,
                    &*self.key_provider,
                    &*self.did_method_provider,
                    &*self.client,
                    &revocation_params,
                )
                .await?;

                let token = std::str::from_utf8(&lvvc.credential)
                    .map_err(|e| ServiceError::MappingError(e.to_string()))?
                    .to_string();

                let lvvc_presentation = CredentialPresentation {
                    token,
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
            .holder_submit_proof(
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

        self.proof_repository
            .set_proof_state(
                &proof.id,
                if submit_result.is_ok() {
                    ProofStateEnum::Accepted
                } else {
                    ProofStateEnum::Error
                },
            )
            .await?;

        submit_result
    }

    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
        did_id: DidId,
        key_id: Option<KeyId>,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations::default()),
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
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

        let holder_jwk_key_id = self
            .did_method_provider
            .get_verification_method_id_from_did_and_key(&did, selected_key)
            .await?;

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

            let issuer_response = self
                .protocol_provider
                .get_protocol(&credential.exchange)
                .ok_or(MissingProviderError::ExchangeProtocol(
                    credential.exchange.clone(),
                ))?
                .holder_accept_credential(
                    &credential,
                    &did,
                    selected_key,
                    Some(holder_jwk_key_id.clone()),
                    &format,
                    &storage_access,
                    tx_code.clone(),
                    detect_format_with_crypto_suite,
                )
                .await?;

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

            let claims = self
                .extract_claims(&credential.id, &issuer_response.credential, schema)
                .await?;

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
                    claims: Some(claims),
                })
                .await?;
        }

        Ok(())
    }

    async fn extract_claims(
        &self,
        credential_id: &CredentialId,
        credential: &str,
        schema: &CredentialSchema,
    ) -> Result<Vec<Claim>, ServiceError> {
        let credential_format = &schema.format;

        let formatter = self
            .formatter_provider
            .get_formatter(credential_format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(credential_format.to_owned()),
            ))?;

        let credential = formatter
            .extract_credentials_unverified(credential)
            .await
            .map_err(ServiceError::FormatterError)?;

        let mut collected_claims: Vec<Claim> = Vec::new();

        let claim_schemas = schema
            .claim_schemas
            .as_ref()
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::MissingClaimSchemas,
            ))?;
        let now = OffsetDateTime::now_utc();

        for (key, value) in credential.claims.values {
            let this_claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.key == key)
                .ok_or(ServiceError::BusinessLogic(
                    BusinessLogicError::MissingClaimSchemas,
                ))?;

            collected_claims.extend(value_to_model_claims(
                *credential_id,
                claim_schemas,
                &value,
                now,
                &this_claim_schema.schema,
                &key,
            )?);
        }

        Ok(collected_claims)
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
                .holder_reject_credential(&credential)
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
                    claims: None, //TODO!
                })
                .await?;
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
