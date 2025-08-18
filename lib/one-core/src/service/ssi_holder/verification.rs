use std::collections::HashMap;

use futures::TryFutureExt;
use shared_types::ProofId;
use url::Url;

use super::SSIHolderService;
use super::dto::{HandleInvitationResultDTO, PresentationSubmitRequestDTO};
use crate::common_mapper::{
    IdentifierRole, NESTED_CLAIM_MARKER, RemoteIdentifierRelation, get_or_create_identifier,
};
use crate::common_validator::throw_if_latest_proof_state_not_eq;
use crate::config::core_config::{Fields, RevocationType};
use crate::config::validator::transport::{
    SelectedTransportType, validate_and_select_transport_type,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::CredentialRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::{InteractionId, InteractionRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::revocation::lvvc::holder_fetch::holder_get_lvvc;
use crate::provider::verification_protocol::dto::{
    InvitationResponseDTO, PresentedCredential, UpdateResponse,
};
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPHolderInteractionData;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ErrorCodeMixin, MissingProviderError, ServiceError,
    ValidationError,
};
use crate::service::ssi_holder::validator::validate_holder_capabilities;
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::oidc::detect_format_with_crypto_suite;

impl SSIHolderService {
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
                    verifier_identifier: Some(IdentifierRelations {
                        organisation: Some(OrganisationRelations::default()),
                        did: Some(Default::default()),
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

        let (state, error_metadata) = if let Err(err) = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.protocol.clone(),
            ))?
            .holder_reject_proof(&proof)
            .await
        {
            let error_metadata = Some(HistoryErrorMetadata {
                error_code: err.error_code(),
                message: err.to_string(),
            });
            (ProofStateEnum::Error, error_metadata)
        } else {
            (ProofStateEnum::Rejected, None)
        };
        self.proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    state: Some(state),
                    ..Default::default()
                },
                error_metadata,
            )
            .await?;

        Ok(())
    }

    pub async fn submit_proof(
        &self,
        submission: PresentationSubmitRequestDTO,
    ) -> Result<(), ServiceError> {
        if submission.submit_credentials.is_empty() {
            return Err(BusinessLogicError::EmptyPresentationSubmission.into());
        }

        let Some(proof) = self
            .proof_repository
            .get_proof_by_interaction_id(
                &submission.interaction_id,
                &ProofRelations {
                    holder_identifier: Some(IdentifierRelations {
                        organisation: Some(OrganisationRelations::default()),
                        did: Some(Default::default()),
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

        let holder_identifier = match (submission.did_id, submission.identifier_id) {
            (Some(did_id), None) => self
                .identifier_repository
                .get_from_did_id(
                    did_id,
                    &IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(ServiceError::from(ValidationError::DidNotFound))?,
            (None, Some(identifier_id)) => self
                .identifier_repository
                .get(
                    identifier_id,
                    &IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(Default::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(ServiceError::from(EntityNotFoundError::Identifier(
                    identifier_id,
                )))?,
            (Some(_), Some(_)) | (None, None) => {
                return Err(BusinessLogicError::OverlappingHolderDidWithIdentifier.into());
            }
        };

        let mut credentials = HashMap::new();
        for submitted_credential in submission.submit_credentials.values() {
            let credential = self
                .credential_repository
                .get_credential(
                    &submitted_credential.credential_id,
                    &CredentialRelations {
                        claims: Some(ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        }),
                        holder_identifier: Some(IdentifierRelations {
                            did: Some(DidRelations {
                                keys: Some(KeyRelations::default()),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }),
                        key: Some(KeyRelations::default()),
                        schema: Some(CredentialSchemaRelations::default()),
                        ..Default::default()
                    },
                )
                .await?
                .ok_or(EntityNotFoundError::Credential(
                    submitted_credential.credential_id,
                ))?;
            credentials.insert(credential.id, credential);
        }

        for credential in credentials.values() {
            let Some(schema) = &credential.schema else {
                return Err(ServiceError::MappingError(format!(
                    "missing credential schema for credential {}",
                    credential.id
                )));
            };
            let formatter = self
                .formatter_provider
                .get_credential_formatter(&schema.format)
                .ok_or(MissingProviderError::Formatter(schema.format.to_string()))?;
            if !formatter
                .get_capabilities()
                .holder_identifier_types
                .contains(&holder_identifier.r#type.clone().into())
            {
                Err(BusinessLogicError::IncompatibleHolderIdentifier)?
            }
        }

        let holder_did = holder_identifier
            .did
            .to_owned()
            .ok_or(ServiceError::MappingError(
                "missing identifier did".to_string(),
            ))?;

        let key_filter = KeyFilter::role_filter(KeyRole::Authentication);
        let selected_key = match submission.key_id {
            Some(key_id) => holder_did
                .find_key(&key_id, &key_filter)?
                .ok_or(ValidationError::KeyNotFound)?,
            None => holder_did
                .find_first_matching_key(&key_filter)?
                .ok_or(ValidationError::KeyNotFound)?,
        };

        let holder_jwk_key_id = holder_did.verification_method_id(selected_key);
        let selected_key = &selected_key.key;

        let verification_protocol = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.protocol.clone(),
            ))?;

        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let interaction_data: serde_json::Value = proof
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
            self.certificate_repository.clone(),
            self.certificate_validator.clone(),
            self.key_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
        );

        let presentation_definition = verification_protocol
            .holder_get_presentation_definition(&proof, interaction_data.clone(), &storage_access)
            .await?;

        let requested_credentials: Vec<_> = presentation_definition
            .request_groups
            .into_iter()
            .flat_map(|group| group.requested_credentials)
            .collect();

        let mut submitted_claims: Vec<Claim> = vec![];
        let mut credential_presentations: Vec<PresentedCredential> = vec![];
        let holder_binding_ctx =
            verification_protocol.holder_get_holder_binding_context(&proof, interaction_data)?;
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
                        .get(&credential_request.credential_id)
                        .ok_or(ServiceError::MappingError(format!(
                            "no matching key for credential_id `{}`",
                            credential_request.credential_id
                        )))?
                        .to_owned())
                })
                .collect::<Result<Vec<String>, ServiceError>>()?;

            let credential =
                credentials
                    .get(&credential_request.credential_id)
                    .ok_or(ServiceError::Other(format!(
                        "Failed to find preloaded credential with id {}",
                        credential_request.credential_id
                    )))?;

            let credential_blob_id =
                credential
                    .credential_blob_id
                    .ok_or(BusinessLogicError::MissingCredentialData {
                        credential_id: credential_request.credential_id,
                    })?;

            let db_blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)
                .await
                .ok_or_else(|| {
                    MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                })?;
            let credential_blob = db_blob_storage.get(&credential_blob_id).await?.ok_or(
                BusinessLogicError::MissingCredentialData {
                    credential_id: credential_request.credential_id,
                },
            )?;

            let credential_data = credential_blob.value.as_slice();
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
                .get_credential_formatter(&format)
                .ok_or(MissingProviderError::Formatter(format.to_string()))?;

            validate_holder_capabilities(
                self.config.as_ref(),
                &holder_did,
                &holder_identifier,
                selected_key,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )?;

            let credential_presentation = CredentialPresentation {
                token: credential_content.to_owned(),
                disclosed_keys: submitted_keys.to_owned(),
            };

            let authn_fn = credential
                .key
                .as_ref()
                .map(|key| {
                    self.key_provider.get_signature_provider(
                        key,
                        None,
                        self.key_algorithm_provider.clone(),
                    )
                })
                .transpose()?;

            let formatted_credential_presentation = formatter
                .format_credential_presentation(
                    credential_presentation,
                    holder_binding_ctx.clone(),
                    authn_fn,
                )
                .await?;

            let mut presented_credential = PresentedCredential {
                presentation: formatted_credential_presentation.to_owned(),
                validity_credential_presentation: None,
                credential_schema: credential_schema.clone(),
                request: requested_credential.to_owned(),
            };

            let revocation_method: Fields<RevocationType> = self
                .config
                .revocation
                .get(&credential_schema.revocation_method)?;
            if revocation_method.r#type == RevocationType::Lvvc {
                let extracted = formatter
                    .extract_credentials_unverified(
                        &formatted_credential_presentation,
                        Some(credential_schema),
                    )
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
                    credential,
                    &credential_status,
                    &*self.validity_credential_repository,
                    &*self.key_provider,
                    &self.key_algorithm_provider,
                    &*self.client,
                    &revocation_params,
                    false,
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
                    .format_credential_presentation(lvvc_presentation, None, None)
                    .await?;

                presented_credential.validity_credential_presentation =
                    Some(formatted_lvvc_presentation);
            }
            credential_presentations.push(presented_credential);
        }

        let submit_result = verification_protocol
            .holder_submit_proof(
                &proof,
                credential_presentations,
                &holder_did,
                selected_key,
                Some(holder_jwk_key_id),
            )
            .map_err(ServiceError::from)
            .and_then(|submit_result| async {
                self.resolve_update_proof_response(proof.id, submit_result)
                    .await
            })
            .await;

        let (state, error_metadata) = if let Err(ref err) = submit_result {
            let error_metadata = Some(HistoryErrorMetadata {
                error_code: err.error_code(),
                message: err.to_string(),
            });
            (ProofStateEnum::Error, error_metadata)
        } else {
            (ProofStateEnum::Accepted, None)
        };
        self.proof_repository
            .update_proof(
                &proof.id,
                UpdateProofRequest {
                    holder_identifier_id: Some(holder_identifier.id),
                    state: Some(state),
                    ..Default::default()
                },
                error_metadata,
            )
            .await?;

        self.proof_repository
            .set_proof_claims(&proof.id, submitted_claims)
            .await?;

        submit_result
    }

    pub(super) async fn handle_verification_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        transport: Option<Vec<String>>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        let (verification_exchange, verification_protocol) = self
            .verification_protocol_provider
            .detect_protocol(&url)
            .ok_or(ServiceError::MissingExchangeProtocol(
                "Cannot detect exchange protocol".to_string(),
            ))?;

        let storage_access = StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.certificate_repository.clone(),
            self.certificate_validator.clone(),
            self.key_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
        );

        let transport = validate_and_select_transport_type(
            &transport,
            &self.config.transport,
            &verification_protocol.get_capabilities(),
        )?;
        let transport = match transport {
            SelectedTransportType::Single(s) => s,
            SelectedTransportType::Multiple(vec) => vec
                .into_iter()
                .next()
                .ok_or_else(|| ValidationError::TransportNotAllowedForExchange)?,
        };

        let InvitationResponseDTO {
            mut proof,
            interaction_id,
        } = verification_protocol
            .holder_handle_invitation(url, organisation, &storage_access, transport)
            .await?;

        proof.protocol = verification_exchange;

        self.fill_verifier_in_proof(&mut proof).await?;

        self.proof_repository.create_proof(proof.to_owned()).await?;

        Ok(HandleInvitationResultDTO::ProofRequest {
            interaction_id,
            proof_id: proof.id,
        })
    }

    async fn fill_verifier_in_proof(&self, proof: &mut Proof) -> Result<(), ServiceError> {
        if let Some(interaction) = proof.interaction.as_ref() {
            let deserialized: Result<OpenID4VPHolderInteractionData, _> =
                deserialize_interaction_data(interaction.data.as_ref());
            if let Ok(data) = deserialized {
                if let Some(details) = data.verifier_details {
                    let (identifier, verifier_identifier_relation) = get_or_create_identifier(
                        &*self.did_method_provider,
                        &*self.did_repository,
                        &*self.certificate_repository,
                        &*self.certificate_validator,
                        &*self.key_repository,
                        &*self.key_algorithm_provider,
                        &*self.identifier_repository,
                        &interaction.organisation,
                        &details,
                        IdentifierRole::Verifier,
                    )
                    .await?;
                    proof.verifier_identifier = Some(identifier);
                    match verifier_identifier_relation {
                        RemoteIdentifierRelation::Certificate(certificate) => {
                            proof.verifier_certificate = Some(certificate)
                        }
                        RemoteIdentifierRelation::Key(key) => proof.verifier_key = Some(key),
                        _ => {}
                    };
                }
            }
        }
        Ok(())
    }

    async fn resolve_update_proof_response(
        &self,
        proof_id: ProofId,
        update_response: UpdateResponse,
    ) -> Result<(), ServiceError> {
        if let Some(update_proof) = update_response.update_proof {
            self.proof_repository
                .update_proof(&proof_id, update_proof, None)
                .await?;
        }
        Ok(())
    }
}
