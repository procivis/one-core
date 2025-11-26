use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ApplicableCredentialOrFailureHintEnum::ApplicableCredentials;
use futures::TryFutureExt;
use itertools::Itertools;
use shared_types::{CredentialId, ProofId};
use url::Url;

use super::SSIHolderService;
use super::dto::{
    HandleInvitationResultDTO, PresentationSubmitRequestDTO,
    PresentationSubmitV2CredentialRequestDTO, PresentationSubmitV2RequestDTO,
};
use crate::config::core_config::{Fields, RevocationType};
use crate::config::validator::transport::{
    SelectedTransportType, validate_and_select_transport_type,
};
use crate::mapper::oidc::detect_format_with_crypto_suite;
use crate::mapper::{
    IdentifierRole, NESTED_CLAIM_MARKER, RemoteIdentifierRelation, get_or_create_identifier,
    paths_to_leafs,
};
use crate::model::claim::{Claim, ClaimRelations};
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{Credential, CredentialRelations};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::DidRelations;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::IdentifierRelations;
use crate::model::interaction::{InteractionId, InteractionRelations};
use crate::model::key::KeyRelations;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::proof::{Proof, ProofRelations, ProofStateEnum, UpdateProofRequest};
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::{CredentialPresentation, HolderBindingCtx};
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::revocation::lvvc::holder_fetch::holder_get_lvvc;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::{
    ApplicableCredentialOrFailureHintEnum, CredentialDetailClaimExtResponseDTO,
    FormattedCredentialPresentation, InvitationResponseDTO, PresentationDefinitionVersion,
    PresentationReference, UpdateResponse,
};
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPHolderInteractionData;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimValueResponseDTO,
};
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, ErrorCodeMixin, MissingProviderError, ServiceError,
    ValidationError,
};
use crate::service::ssi_holder::mapper::holder_did_key_jwk_from_credential;
use crate::service::storage_proxy::StorageProxyImpl;
use crate::validator::{
    throw_if_endpoint_version_incompatible, throw_if_latest_proof_state_not_eq,
};

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

        let mut credentials = HashMap::new();
        for submitted_credentials in submission.submit_credentials.values() {
            for submitted_credential in submitted_credentials {
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
                                key: Some(KeyRelations::default()),
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
        }

        let verification_protocol = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.protocol.clone(),
            ))?;

        throw_if_endpoint_version_incompatible(
            &*verification_protocol,
            &PresentationDefinitionVersion::V1,
        )?;
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let interaction_data: serde_json::Value = proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.data.as_ref())
            .map(|interaction| serde_json::from_slice(interaction))
            .ok_or_else(|| ServiceError::MappingError("missing interaction".into()))?
            .map_err(|err| ServiceError::MappingError(err.to_string()))?;

        let presentation_definition = verification_protocol
            .holder_get_presentation_definition(
                &proof,
                interaction_data.clone(),
                &self.storage_access(),
            )
            .await?;

        let requested_credentials: Vec<_> = presentation_definition
            .request_groups
            .into_iter()
            .flat_map(|group| group.requested_credentials)
            .collect();

        let mut submitted_claims: Vec<Claim> = vec![];
        let mut credential_presentations: Vec<FormattedCredentialPresentation> = vec![];
        let holder_binding_ctx =
            verification_protocol.holder_get_holder_binding_context(&proof, interaction_data)?;

        for (requested_credential_id, submitted_credentials) in submission.submit_credentials {
            let requested_credential = requested_credentials
                .iter()
                .find(|credential| credential.id == requested_credential_id)
                .ok_or(ServiceError::MappingError(format!(
                    "requested credential `{requested_credential_id}` not found"
                )))?;

            if requested_credential.multiple.unwrap_or(false) && submitted_credentials.len() > 1 {
                return Err(ServiceError::MappingError(format!(
                    "multiple credentials not supported for requested credential `{requested_credential_id}`"
                )));
            }

            for submitted_credential in submitted_credentials {
                let submitted_keys = requested_credential
                    .fields
                    .iter()
                    .filter(|field| submitted_credential.submit_claims.contains(&field.id))
                    .map(|field| {
                        Ok(field
                            .key_map
                            .get(&submitted_credential.credential_id)
                            .ok_or(ServiceError::MappingError(format!(
                                "no matching key for credential_id `{}`",
                                submitted_credential.credential_id
                            )))?
                            .to_owned())
                    })
                    .collect::<Result<Vec<String>, ServiceError>>()?;

                let credential = credentials.get(&submitted_credential.credential_id).ok_or(
                    ServiceError::Other(format!(
                        "Failed to find preloaded credential with id {}",
                        submitted_credential.credential_id
                    )),
                )?;

                let credential_blob_id = credential.credential_blob_id.ok_or(
                    BusinessLogicError::MissingCredentialData {
                        credential_id: submitted_credential.credential_id,
                    },
                )?;

                let db_blob_storage = self
                    .blob_storage_provider
                    .get_blob_storage(BlobStorageType::Db)
                    .await
                    .ok_or_else(|| {
                        MissingProviderError::BlobStorage(BlobStorageType::Db.to_string())
                    })?;
                let credential_blob = db_blob_storage.get(&credential_blob_id).await?.ok_or(
                    BusinessLogicError::MissingCredentialData {
                        credential_id: submitted_credential.credential_id,
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
                    for key in &submitted_keys {
                        // handle nested path by checking the prefix
                        if claim
                            .path
                            .starts_with(&format!("{key}{NESTED_CLAIM_MARKER}"))
                            || claim.path == *key
                                && submitted_claims.iter().all(|c| c.id != claim.id)
                        {
                            submitted_claims.push(claim.to_owned());
                        }
                    }
                }

                let formatter =
                    self.formatter_for_blob_and_schema(credential_content, credential_schema)?;
                let credential_presentation = CredentialPresentation {
                    token: credential_content.to_owned(),
                    disclosed_keys: submitted_keys.to_owned(),
                };
                let (holder_did, key, jwk_key_id) = holder_did_key_jwk_from_credential(credential)?;
                let (presentation, validity_credential_presentation) = self
                    .prepare_credential_presentation(
                        credential_presentation,
                        holder_binding_ctx.clone(),
                        credential,
                        &*formatter,
                    )
                    .await?;

                let presented_credential = FormattedCredentialPresentation {
                    presentation,
                    validity_credential_presentation,
                    credential_schema: credential_schema.clone(),
                    reference: PresentationReference::PresentationExchange(
                        requested_credential.to_owned(),
                    ),
                    holder_did,
                    key,
                    jwk_key_id,
                };
                credential_presentations.push(presented_credential);
            }
        }

        self.submit_and_update_proof(
            &proof,
            &*verification_protocol,
            credential_presentations,
            submitted_claims,
        )
        .await
    }

    async fn submit_and_update_proof(
        &self,
        proof: &Proof,
        verification_protocol: &dyn VerificationProtocol,
        credential_presentations: Vec<FormattedCredentialPresentation>,
        submitted_claims: Vec<Claim>,
    ) -> Result<(), ServiceError> {
        let submit_result = verification_protocol
            .holder_submit_proof(proof, credential_presentations)
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

    fn formatter_for_blob_and_schema(
        &self,
        credential_content: &str,
        credential_schema: &CredentialSchema,
    ) -> Result<Arc<dyn CredentialFormatter>, ServiceError> {
        let format =
            detect_format_with_crypto_suite(&credential_schema.format, credential_content)?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format)
            .ok_or(MissingProviderError::Formatter(format.to_string()))?;
        Ok(formatter)
    }

    /// Formats the given presentation using the appropriate formatter.
    /// Depending on the revocation method used, another validity credential
    /// is returned along with it.
    async fn prepare_credential_presentation(
        &self,
        credential_presentation: CredentialPresentation,
        holder_binding_ctx: Option<HolderBindingCtx>,
        credential: &Credential,
        formatter: &dyn CredentialFormatter,
    ) -> Result<(String, Option<String>), ServiceError> {
        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ServiceError::MappingError(
                "credential_schema missing".to_string(),
            ))?;

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

        let presentation = formatter
            .format_credential_presentation(credential_presentation, holder_binding_ctx, authn_fn)
            .await?;

        let revocation_method: Fields<RevocationType> = self
            .config
            .revocation
            .get(&credential_schema.revocation_method)?;
        let lvvc_presentation = if revocation_method.r#type == RevocationType::Lvvc {
            let extracted = formatter
                .extract_credentials_unverified(&presentation, Some(credential_schema))
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
            Some(formatted_lvvc_presentation)
        } else {
            None
        };
        Ok((presentation, lvvc_presentation))
    }

    pub async fn submit_proof_v2(
        &self,
        request: PresentationSubmitV2RequestDTO,
    ) -> Result<(), ServiceError> {
        if request.submission.is_empty() {
            return Err(BusinessLogicError::EmptyPresentationSubmission.into());
        }

        let Some(proof) = self
            .proof_repository
            .get_proof_by_interaction_id(
                &request.interaction_id,
                &ProofRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?
        else {
            return Err(
                BusinessLogicError::MissingProofForInteraction(request.interaction_id).into(),
            );
        };

        let verification_protocol = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                proof.protocol.clone(),
            ))?;

        throw_if_endpoint_version_incompatible(
            &*verification_protocol,
            &PresentationDefinitionVersion::V2,
        )?;
        throw_if_latest_proof_state_not_eq(&proof, ProofStateEnum::Requested)?;

        let interaction_data: serde_json::Value = proof
            .interaction
            .as_ref()
            .and_then(|interaction| interaction.data.as_ref())
            .map(|interaction| serde_json::from_slice(interaction))
            .ok_or_else(|| ServiceError::MappingError("missing interaction".into()))?
            .map_err(|err| ServiceError::MappingError(err.to_string()))?;
        let holder_binding_ctx = verification_protocol
            .holder_get_holder_binding_context(&proof, interaction_data.clone())?;
        let presentation_definition = verification_protocol
            .holder_get_presentation_definition_v2(&proof, interaction_data, &self.storage_access())
            .await?;

        struct CredentialPathsToPresent {
            credential_id: CredentialId,
            // all paths of the presented subtree
            presented_paths: Vec<String>,
        }

        // All the things the user chose to present
        let mut creds_paths_to_present = HashMap::<String, Vec<CredentialPathsToPresent>>::new();
        for (query_id, credential_selection) in request.submission {
            let Some(possible_selections) =
                presentation_definition.credential_queries.get(&query_id)
            else {
                return Err(BusinessLogicError::InvalidPresentationSubmission {
                    reason: format!("Unknown credential query id `{query_id}`"),
                }
                .into());
            };
            let ApplicableCredentials {
                applicable_credentials,
            } = &possible_selections.credential_or_failure_hint
            else {
                return Err(BusinessLogicError::InvalidPresentationSubmission {
                    reason: format!("No applicable credentials for query id `{query_id}`"),
                }
                .into());
            };

            if credential_selection.len() > 1 && !possible_selections.multiple {
                return Err(BusinessLogicError::InvalidPresentationSubmission {
                    reason: format!(
                        "Only one submission allowed for credential query id `{query_id}`"
                    ),
                }
                .into());
            }

            for PresentationSubmitV2CredentialRequestDTO {
                credential_id,
                user_selections,
            } in credential_selection
            {
                let deduplicated: HashSet<&String> = HashSet::from_iter(&user_selections);
                if deduplicated.len() != user_selections.len() {
                    return Err(BusinessLogicError::InvalidPresentationSubmission {
                        reason: format!("Invalid user selections for credential `{credential_id}` for `{query_id}`: user selections contain duplicate paths"),
                    }.into());
                }
                let Some(selected_credential) = applicable_credentials
                    .iter()
                    .find(|&credential| credential.id == credential_id)
                else {
                    return Err(BusinessLogicError::InvalidPresentationSubmission {
                        reason: format!("Credential `{credential_id}` is not applicable for credential query id `{query_id}`"),
                    }.into());
                };

                let presented_paths = CredentialPathsToPresent {
                    credential_id,
                    presented_paths: presented_claim_paths_from_nested_with_selection(
                        selected_credential,
                        user_selections,
                    )?,
                };
                creds_paths_to_present
                    .entry(query_id.clone())
                    .or_default()
                    .push(presented_paths);
            }
        }

        // Check against all the credential set options available
        for (idx, credential_set) in presentation_definition.credential_sets.iter().enumerate() {
            if !credential_set.required {
                // not required -> nothing to check
                continue;
            }
            if !credential_set.options.iter().any(|option| {
                option
                    .iter()
                    .all(|query_id| creds_paths_to_present.contains_key(query_id))
            }) {
                let string = credential_set
                    .options
                    .iter()
                    .map(|opts| format!("[{}]", opts.join(", ")))
                    .join(", ");
                return Err(BusinessLogicError::InvalidPresentationSubmission { reason: format!("No option satisfied for mandatory credential set with index `{idx}`. Options are: [{}]", &string) }.into());
            }
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::BlobStorage("Missing blobstorage type DB".to_string()),
            ))?;
        let mut submitted_claims = vec![];
        let mut credential_presentations = vec![];
        for (query_id, credential_selection) in creds_paths_to_present {
            for CredentialPathsToPresent {
                credential_id,
                presented_paths,
            } in credential_selection
            {
                let credential = self
                    .credential_repository
                    .get_credential(
                        &credential_id,
                        &CredentialRelations {
                            claims: Some(Default::default()),
                            key: Some(Default::default()),
                            holder_identifier: Some(IdentifierRelations {
                                did: Some(DidRelations {
                                    keys: Some(Default::default()),
                                    ..Default::default()
                                }),
                                key: Some(Default::default()),
                                ..Default::default()
                            }),
                            schema: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(EntityNotFoundError::Credential(credential_id))?;
                let blob_id = credential
                    .credential_blob_id
                    .ok_or(ServiceError::MappingError(format!(
                        "Missing blob id on credential `{credential_id}`"
                    )))?;
                let credential_blob =
                    blob_storage
                        .get(&blob_id)
                        .await?
                        .ok_or(ServiceError::MappingError(format!(
                            "Blob with id `{blob_id}` (belonging to credential `{credential_id}`) not found"

                        )))?;

                let credential_content = std::str::from_utf8(&credential_blob.value)
                    .map_err(|e| ServiceError::MappingError(e.to_string()))?;

                let credential_schema =
                    credential
                        .schema
                        .as_ref()
                        .ok_or(ServiceError::MappingError(
                            "credential_schema missing".to_string(),
                        ))?;
                let formatter =
                    self.formatter_for_blob_and_schema(credential_content, credential_schema)?;

                let credential_presentation = CredentialPresentation {
                    token: credential_content.to_owned(),
                    // credential formatters do not use intermediary claims
                    disclosed_keys: paths_to_leafs(&presented_paths),
                };
                let (presentation, validity_credential_presentation) = self
                    .prepare_credential_presentation(
                        credential_presentation,
                        holder_binding_ctx.clone(),
                        &credential,
                        &*formatter,
                    )
                    .await?;

                let (holder_did, key, jwk_key_id) =
                    holder_did_key_jwk_from_credential(&credential)?;
                let presented_credential = FormattedCredentialPresentation {
                    presentation,
                    validity_credential_presentation,
                    credential_schema: credential_schema.clone(),
                    reference: PresentationReference::Dcql {
                        credential_query_id: query_id.clone(),
                    },
                    holder_did,
                    key,
                    jwk_key_id,
                };
                credential_presentations.push(presented_credential);
                let mut claims = credential
                    .claims
                    .ok_or(ServiceError::MappingError(format!(
                        "Missing claims on credential `{credential_id}`"
                    )))?
                    .into_iter()
                    .filter(|c| presented_paths.contains(&c.path))
                    .collect();
                submitted_claims.append(&mut claims);
            }
        }
        self.submit_and_update_proof(
            &proof,
            &*verification_protocol,
            credential_presentations,
            submitted_claims,
        )
        .await
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
            .holder_handle_invitation(url, organisation, &self.storage_access(), transport)
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
            if let Ok(data) = deserialized
                && let Some(details) = data.verifier_details
            {
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

    fn storage_access(&self) -> StorageProxyImpl {
        StorageProxyImpl::new(
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
        )
    }
}

fn presented_claim_paths_from_nested_with_selection(
    credential: &CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO>,
    mut user_selections: Vec<String>,
) -> Result<Vec<String>, ServiceError> {
    let mut presented_paths = vec![];
    credential.claims.iter().try_for_each(|child_claim| {
        select_claims(child_claim, &mut user_selections, &mut presented_paths)
    })?;

    if !user_selections.is_empty() {
        return Err(BusinessLogicError::InvalidPresentationSubmission {
            reason: format!("Invalid user selections for credential `{}`. The following selection paths do not match any known claim: [{}]", credential.id, user_selections.join(", ")),
        }.into());
    }

    Ok(presented_paths)
}

fn select_claims(
    current: &CredentialDetailClaimExtResponseDTO, // is selected
    user_selections: &mut Vec<String>,
    selected: &mut Vec<String>,
) -> Result<(), ServiceError> {
    if !is_selected_claim(current, user_selections)? {
        // not selected, return
        return Ok(());
    }
    selected.push(current.path.clone());

    let DetailCredentialClaimValueResponseDTO::Nested(child_claims) = &current.value else {
        return Ok(()); // no children to select
    };
    child_claims
        .iter()
        .try_for_each(|child_claim| select_claims(child_claim, user_selections, selected))
}

fn is_selected_claim(
    claim: &CredentialDetailClaimExtResponseDTO,
    user_selections: &mut Vec<String>,
) -> Result<bool, ServiceError> {
    let user_selection = user_selections
        .iter()
        .find_position(|selection| **selection == claim.path);
    let is_selected = user_selection.is_some();

    if let Some((idx, _)) = user_selection {
        if !claim.user_selection {
            return Err(BusinessLogicError::InvalidPresentationSubmission {
                reason: format!("Path `{}` is not a valid user selection", &claim.path),
            }
            .into());
        }
        // remove user selections from the list once found
        user_selections.swap_remove(idx);
    }

    let is_child_or_parent_of_selected = user_selections.iter().any(|selected_path| {
        selected_path.starts_with(&format!("{}/", &claim.path))
            || claim.path.starts_with(&format!("{}/", &selected_path))
    });
    Ok(claim.required || is_selected || is_child_or_parent_of_selected)
}
