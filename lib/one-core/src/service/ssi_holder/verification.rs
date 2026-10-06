use std::collections::{HashMap, HashSet};

use futures_util::FutureExt;
use itertools::Itertools;
use shared_types::{CredentialId, EcosystemId, InteractionId, ProofId, TransactionDataId};
use standardized_types::openid4vp::dcql::CredentialQueryId;
use url::Url;

use super::SSIHolderService;
use super::dto::{
    HandleInvitationResultDTO, PresentationSubmitV2CredentialRequestDTO,
    PresentationSubmitV2RequestDTO,
};
use super::error::HolderServiceError;
use super::mapper::holder_did_key_jwk_from_credential;
use crate::clock::now_utc;
use crate::config::core_config::BlobStorageType;
use crate::config::validator::transport::{
    SelectedTransportType, validate_and_select_transport_type,
};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::credential_schema_claim::presented_paths_to_disclosed_keys;
use crate::mapper::oidc::detect_format_with_crypto_suite;
use crate::model::credential::{Clearable, Credential, UpdateCredentialRequest};
use crate::model::history::HistoryErrorMetadata;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofClaim, ProofStateEnum, UpdateProofRequest};
use crate::model::relation::{OptionalRelatedRefExt, Related};
use crate::proto::identifier_creator::{IdentifierName, IdentifierRole, RemoteIdentifierRelation};
use crate::provider::credential_formatter::CredentialFormatter;
use crate::provider::credential_formatter::model::CredentialPresentation;
use crate::provider::issuance_protocol::deserialize_interaction_data;
use crate::provider::verification_protocol::VerificationProtocol;
use crate::provider::verification_protocol::dto::ApplicableCredentialOrFailureHintEnum::ApplicableCredentials;
use crate::provider::verification_protocol::dto::{
    CredentialDetailClaimExtResponseDTO, FormattedCredentialPresentation, InvitationResponseDTO,
    PresentationDefinitionV2ResponseDTO, PresentationDefinitionVersion, UpdateResponse,
};
use crate::provider::verification_protocol::openid4vp::model::OpenID4VPHolderInteractionData;
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{
    CredentialDetailResponseDTO, DetailCredentialClaimValueResponseDTO,
};
use crate::validator::{throw_if_endpoint_version_incompatible, throw_if_proof_state_not_eq};

impl SSIHolderService {
    pub async fn reject_proof_request(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), HolderServiceError> {
        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(interaction_id)
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    HolderServiceError::MissingProofForInteraction(*interaction_id)
                }
                error => error.error_while("getting proof").into(),
            })?;

        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Requested)
            .error_while("checking proof state")?;

        let (state, error_metadata) = if let Err(err) = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)?
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
            .await
            .error_while("updating proof")?;

        tracing::info!("Rejected proof request {}", proof.id);
        Ok(())
    }

    async fn submit_and_update_proof(
        &self,
        proof: &Proof,
        verification_protocol: &dyn VerificationProtocol,
        credential_presentations: Vec<FormattedCredentialPresentation>,
        submitted_claims: Vec<ProofClaim>,
    ) -> Result<(), HolderServiceError> {
        let submit_result = verification_protocol
            .holder_submit_proof(proof, credential_presentations)
            .await
            .error_while("submitting proof");

        let submit_error = match submit_result {
            Ok(update_response) => self
                .resolve_update_proof_response(proof.id, update_response)
                .await
                .error_while("updating proof")
                .err(),
            Err(err) => Some(err),
        };

        // A rejected transaction data assignment is detected before anything is
        // sent to the verifier; report it as a request error and keep the proof
        // actionable instead of moving it to Error.
        let submit_error = match submit_error {
            Some(err) if err.error_code() == ErrorCode::BR_0459 => return Err(err.into()),
            other => other,
        };

        let (state, error_metadata) = if let Some(ref err) = submit_error {
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
            .await
            .error_while("updating proof")?;

        // Repeated queries may disclose the same claim from the same item.
        // Keep distinct presented credentials as separate proof inputs.
        self.proof_repository
            .set_proof_claims(
                &proof.id,
                submitted_claims
                    .into_iter()
                    .unique_by(|c| (c.credential.id(), c.claim.id))
                    .collect(),
            )
            .await
            .error_while("setting proof claims")?;

        match submit_error {
            Some(err) => Err(err.into()),
            None => Ok(()),
        }
    }

    /// Formats the given presentation using the appropriate formatter.
    async fn prepare_credential_presentation(
        &self,
        credential_presentation: CredentialPresentation,
        formatter: &dyn CredentialFormatter,
    ) -> Result<String, HolderServiceError> {
        let presentation = formatter
            .prepare_selective_disclosure(credential_presentation)
            .await
            .error_while("preparing selective disclosure")?;

        Ok(presentation)
    }

    pub async fn submit_proof_v2(
        &self,
        request: PresentationSubmitV2RequestDTO,
    ) -> Result<(), HolderServiceError> {
        if request.submission.is_empty() {
            return Err(HolderServiceError::EmptyPresentationSubmission);
        }

        let proof = self
            .proof_repository
            .get_proof_by_interaction_id(&request.interaction_id)
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    HolderServiceError::MissingProofForInteraction(request.interaction_id)
                }
                error => error.error_while("getting proof").into(),
            })?;

        let verification_protocol = self
            .verification_protocol_provider
            .get_protocol(&proof.protocol)?;

        throw_if_endpoint_version_incompatible(
            &*verification_protocol,
            &PresentationDefinitionVersion::V2,
        )
        .error_while("checking endpoint version")?;
        throw_if_proof_state_not_eq(&proof, ProofStateEnum::Requested)
            .error_while("checking proof state")?;

        let interaction = proof
            .interaction
            .as_ref()
            .ok_or_else(|| HolderServiceError::MappingError("missing interaction".into()))?
            .as_ref()
            .await?;
        let interaction_data = interaction
            .data
            .as_ref()
            .ok_or_else(|| HolderServiceError::MappingError("missing interaction data".into()))?;

        let interaction_data: serde_json::Value = serde_json::from_slice(interaction_data)
            .map_err(|err| HolderServiceError::MappingError(err.to_string()))?;
        let submitted_credential_ids = request
            .submission
            .values()
            .flatten()
            .map(|selection| selection.credential_id)
            .unique()
            .collect::<Vec<_>>();
        let presentation_definition = verification_protocol
            .holder_get_presentation_definition_v2(
                &proof,
                interaction_data,
                &submitted_credential_ids,
            )
            .await
            .error_while("getting presentation definition V2")?;

        // All the things the user chose to present
        let mut creds_paths_to_present = HashMap::<String, Vec<CredentialPathsToPresent>>::new();
        for (query_id, credential_selection) in request.submission {
            let paths_to_present = get_credential_paths_to_present(
                &query_id,
                credential_selection,
                &presentation_definition,
            )?;

            creds_paths_to_present.insert(query_id, paths_to_present);
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
                return Err(HolderServiceError::InvalidPresentationSubmission {
                    reason: format!(
                        "No option satisfied for mandatory credential set with index `{idx}`. Options are: [{}]",
                        &string
                    ),
                });
            }
        }

        let mut submitted_claims = vec![];
        let mut credential_presentations = vec![];
        let mut consumed_items = vec![];
        for (query_id, credential_selection) in creds_paths_to_present {
            for selection in credential_selection {
                let SubmissionItem {
                    presentation,
                    claims,
                    consumed_item,
                } = self
                    .get_credential_presentation(query_id.to_owned().into(), selection)
                    .await?;

                credential_presentations.push(presentation);
                submitted_claims.extend(claims);
                if let Some(item) = consumed_item {
                    consumed_items.push(item);
                }
            }
        }

        // Do this before submitting the proof because the credentials are potentially sent to the verifier
        // even if the operation fails.
        self.mark_batch_items_as_consumed(consumed_items).await?;
        self.submit_and_update_proof(
            &proof,
            &*verification_protocol,
            credential_presentations,
            submitted_claims,
        )
        .await?;

        tracing::info!("Submitted presentation V2 for proof request {}", proof.id);
        Ok(())
    }

    async fn mark_batch_items_as_consumed(
        &self,
        consumed_items: Vec<CredentialId>,
    ) -> Result<(), HolderServiceError> {
        if !consumed_items.is_empty() {
            let now = now_utc();
            self.transaction_manager
                .tx(async {
                    for item in consumed_items.into_iter().unique() {
                        self.credential_repository
                            .update_credential(
                                item,
                                UpdateCredentialRequest {
                                    consumed_at: Clearable::ForceSet(Some(now)),
                                    ..Default::default()
                                },
                            )
                            .await
                            .error_while(format!("marking credential {item} as consumed"))?;
                    }
                    Ok::<_, HolderServiceError>(())
                }
                .boxed())
                .await
                .error_while("marking batch items as consumed")??;
        }
        Ok(())
    }

    pub(super) async fn handle_verification_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        transport: Option<Vec<String>>,
        user_selected_ecosystem: Option<EcosystemId>,
    ) -> Result<HandleInvitationResultDTO, HolderServiceError> {
        let (protocol, verification_protocol) = self
            .verification_protocol_provider
            .detect_protocol(&url)
            .ok_or(HolderServiceError::MissingExchangeProtocol(
                "Cannot detect exchange protocol".to_string(),
            ))?;

        let transport = validate_and_select_transport_type(
            &transport,
            &self.config.transport,
            &verification_protocol.get_capabilities(),
        )
        .error_while("validating transport")?;
        let transport = match transport {
            SelectedTransportType::Single(s) => s,
            SelectedTransportType::Multiple(vec) => vec
                .into_iter()
                .next()
                .ok_or(HolderServiceError::TransportNotAllowedForExchange)?,
        };

        let InvitationResponseDTO {
            mut proof,
            interaction_id,
            ecosystem_artifact,
        } = verification_protocol
            .holder_handle_invitation(url, organisation, transport)
            .await
            .error_while("handling invitation")?;

        let resolved = self
            .ecosystem_resolver
            .resolve(
                interaction_id,
                &[ecosystem_artifact],
                user_selected_ecosystem.as_ref(),
            )
            .await
            .error_while("resolving ecosystem")?;

        proof.protocol = protocol.clone();
        proof.ecosystem = resolved.ecosystem.to_owned();

        self.fill_verifier_in_proof(&mut proof).await?;

        let proof_id = self
            .proof_repository
            .create_proof(proof)
            .await
            .error_while("creating proof")?;

        Ok(HandleInvitationResultDTO::ProofRequest {
            interaction_id,
            proof_id,
            protocol,
            ecosystem: resolved.ecosystem,
            ecosystem_errors: resolved.outcomes,
        })
    }

    async fn fill_verifier_in_proof(&self, proof: &mut Proof) -> Result<(), HolderServiceError> {
        if let Some(interaction) = proof.interaction.as_ref() {
            let interaction = interaction.as_ref().await?;
            let deserialized: Result<OpenID4VPHolderInteractionData, _> =
                deserialize_interaction_data(interaction.data.as_ref());
            if let Ok(data) = deserialized
                && let Some(details) = data.verifier_details
            {
                let organisation = interaction.organisation.as_ref().await?;
                let (identifier, verifier_identifier_relation) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        &organisation,
                        &details,
                        IdentifierName::PrefixForId(IdentifierRole::Verifier.to_string()),
                        true,
                        None,
                        None,
                    )
                    .await
                    .error_while("creating remote verifier identifier")?;
                proof.verifier_identifier = Some(identifier.into());
                match verifier_identifier_relation {
                    RemoteIdentifierRelation::Certificate(certificate) => {
                        proof.verifier_certificate = Some(certificate.into())
                    }
                    RemoteIdentifierRelation::Key(key) => proof.verifier_key = Some(key.into()),
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
    ) -> Result<(), HolderServiceError> {
        if let Some(update_proof) = update_response.update_proof {
            self.proof_repository
                .update_proof(&proof_id, update_proof, None)
                .await
                .error_while("updating proof")?;
        }
        Ok(())
    }

    async fn get_credential_presentation(
        &self,
        credential_query_id: CredentialQueryId,
        selection: CredentialPathsToPresent,
    ) -> Result<SubmissionItem, HolderServiceError> {
        let CredentialPathsToPresent {
            credential_id,
            presented_paths,
            transaction_data_ids,
        } = selection;
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        // The definition retains the concrete item matching this query's format and
        // displayed claims. Repeated queries can reuse it until submission consumes it.
        let mut presented_credential = self
            .credential_repository
            .get_credential(&credential_id)
            .await
            .error_while("loading presentation credential")?;
        if !presented_credential.is_available_for_presentation(now_utc()) {
            return Err(HolderServiceError::InvalidPresentationSubmission {
                reason: format!(
                    "Credential `{credential_id}` is no longer available for presentation"
                ),
            });
        }
        let consumed_item = matches!(presented_credential, Credential::HolderBatchItem { .. })
            .then_some(presented_credential.common().id);
        let blob_id = presented_credential.credential_blob_id().ok_or_else(|| {
            HolderServiceError::MappingError(format!(
                "Missing blob id on credential `{}`",
                presented_credential.common().id
            ))
        })?;
        let credential_blob = blob_storage
            .get(&blob_id)
            .await
            .error_while("getting credential blob")?
            .ok_or(HolderServiceError::MappingError(format!(
                "Blob with id `{blob_id}` (belonging to credential `{credential_id}`) not found"
            )))?;

        let credential_content = std::str::from_utf8(&credential_blob.value)
            .map_err(|e| HolderServiceError::MappingError(e.to_string()))?
            .into();

        // Presented credential is always a single credential or a batch item.
        *presented_credential.claims_mut()? =
            crate::mapper::credential::stored_credential_claims(&presented_credential)
                .await?
                .into();
        let credential_format = presented_credential
            .format()
            .as_required_ref()
            .await?
            .to_owned();
        let format = detect_format_with_crypto_suite(
            &credential_format.format,
            &credential_content,
            &*self.formatter_provider,
        )
        .error_while("detecting format")?;
        let formatter = self.formatter_provider.get_credential_formatter(&format)?;

        let credential_presentation = CredentialPresentation {
            token: credential_content,
            disclosed_keys: presented_paths_to_disclosed_keys(
                &presented_paths,
                &presented_credential,
            )
            .await
            .error_while("mapping presented paths to disclosed keys")?,
        };
        let presentation = self
            .prepare_credential_presentation(credential_presentation, &*formatter)
            .await?;

        let (holder_did, key, jwk_key_id) =
            holder_did_key_jwk_from_credential(&presented_credential).await?;
        let presentation = FormattedCredentialPresentation {
            presentation,
            credential_format,
            credential_query_id,
            holder_did,
            key,
            jwk_key_id,
            transaction_data_ids,
        };

        let claims = presented_credential
            .claims()?
            .as_ref()
            .await?
            .iter()
            .filter(|c| presented_paths.contains(&c.path))
            .cloned()
            .map(|claim| ProofClaim {
                claim,
                credential: Related::new(credential_id, self.credential_repository.clone()),
            })
            .collect();

        Ok(SubmissionItem {
            presentation,
            claims,
            consumed_item,
        })
    }
}

struct SubmissionItem {
    presentation: FormattedCredentialPresentation,
    claims: Vec<ProofClaim>,
    consumed_item: Option<CredentialId>,
}

struct CredentialPathsToPresent {
    credential_id: CredentialId,
    // all paths of the presented subtree
    presented_paths: Vec<String>,
    // transaction-data ids the client explicitly pinned to this credential
    transaction_data_ids: Vec<TransactionDataId>,
}

fn get_credential_paths_to_present(
    query_id: &String,
    credential_selection: Vec<PresentationSubmitV2CredentialRequestDTO>,
    presentation_definition: &PresentationDefinitionV2ResponseDTO,
) -> Result<Vec<CredentialPathsToPresent>, HolderServiceError> {
    let Some(possible_selections) = presentation_definition.credential_queries.get(query_id) else {
        return Err(HolderServiceError::InvalidPresentationSubmission {
            reason: format!("Unknown credential query id `{query_id}`"),
        });
    };

    if let Some(batches_with_unavailable_items) = presentation_definition
        .matching_batches_with_unavailable_items
        .get(query_id)
    {
        for selection in &credential_selection {
            let has_available_item = match &possible_selections.credential_or_failure_hint {
                ApplicableCredentials {
                    applicable_credentials,
                    ..
                } => applicable_credentials
                    .iter()
                    .any(|item| item.credential.parent_id == Some(selection.credential_id)),
                _ => false,
            };
            if !has_available_item
                && batches_with_unavailable_items.contains(&selection.credential_id)
            {
                return Err(HolderServiceError::BatchExhausted(selection.credential_id));
            }
        }
    }

    let ApplicableCredentials {
        applicable_credentials,
        ..
    } = &possible_selections.credential_or_failure_hint
    else {
        return Err(HolderServiceError::InvalidPresentationSubmission {
            reason: format!("No applicable credentials for query id `{query_id}`"),
        });
    };

    if credential_selection.len() > 1 && !possible_selections.multiple {
        return Err(HolderServiceError::InvalidPresentationSubmission {
            reason: format!("Only one submission allowed for credential query id `{query_id}`"),
        });
    }

    let mut result = vec![];

    for PresentationSubmitV2CredentialRequestDTO {
        credential_id,
        user_selections,
        transaction_data_ids,
    } in credential_selection
    {
        let deduplicated: HashSet<&String> = HashSet::from_iter(&user_selections);
        if deduplicated.len() != user_selections.len() {
            return Err(HolderServiceError::InvalidPresentationSubmission {
                reason: format!(
                    "Invalid user selections for credential `{credential_id}` for `{query_id}`: user selections contain duplicate paths"
                ),
            });
        }
        // Parent IDs resolve to an available matching item, even for batches listed
        // in matching_batches_with_unavailable_items.
        let Some(selected_credential) = applicable_credentials.iter().find(|credential| {
            credential.credential.id == credential_id
                || credential.credential.parent_id == Some(credential_id)
        }) else {
            return Err(HolderServiceError::InvalidPresentationSubmission {
                reason: format!(
                    "Credential `{credential_id}` is not applicable for credential query id `{query_id}`"
                ),
            });
        };

        let presented_paths = presented_claim_paths_from_nested_with_selection(
            &selected_credential.credential,
            user_selections,
        )?;
        result.push(CredentialPathsToPresent {
            credential_id: selected_credential.credential.id,
            presented_paths,
            transaction_data_ids,
        });
    }

    Ok(result)
}

fn presented_claim_paths_from_nested_with_selection(
    credential: &CredentialDetailResponseDTO<CredentialDetailClaimExtResponseDTO>,
    mut user_selections: Vec<String>,
) -> Result<Vec<String>, HolderServiceError> {
    let mut presented_paths = vec![];
    credential.claims.iter().try_for_each(|child_claim| {
        select_claims(child_claim, &mut user_selections, &mut presented_paths)
    })?;

    if !user_selections.is_empty() {
        return Err(HolderServiceError::InvalidPresentationSubmission {
            reason: format!(
                "Invalid user selections for credential `{}`. The following selection paths do not match any known claim: [{}]",
                credential.id,
                user_selections.join(", ")
            ),
        });
    }

    Ok(presented_paths)
}

fn select_claims(
    current: &CredentialDetailClaimExtResponseDTO, // is selected
    user_selections: &mut Vec<String>,
    selected: &mut Vec<String>,
) -> Result<(), HolderServiceError> {
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
) -> Result<bool, HolderServiceError> {
    let user_selection = user_selections
        .iter()
        .find_position(|selection| **selection == claim.path);
    let is_selected = user_selection.is_some();

    if let Some((idx, _)) = user_selection {
        if !claim.user_selection {
            return Err(HolderServiceError::InvalidPresentationSubmission {
                reason: format!("Path `{}` is not a valid user selection", &claim.path),
            });
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
