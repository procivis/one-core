use std::borrow::Cow;
use std::sync::Arc;

use futures_util::FutureExt;
use shared_types::{CredentialId, DidId, EcosystemId, IdentifierId, InteractionId, KeyId};
use standardized_types::oauth2::authorization_request::AuthorizationRequest;
use standardized_types::openid4vci::SigningAlgValue;
use url::Url;
use uuid::Uuid;

use super::SSIHolderService;
use super::dto::{
    ContinueIssuanceResponseDTO, HandleInvitationResultDTO, InitiateIssuanceRequestDTO,
    InitiateIssuanceResponseDTO, OpenIDAuthorizationCodeFlowInteractionData,
};
use super::error::HolderServiceError;
use super::mapper::select_holder_key;
use super::validator::{
    validate_credentials_match_session_organisation, validate_holder_capabilities,
    validate_initiate_issuance_request,
};
use crate::config::core_config::{BlobStorageType, FormatType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::blob::{Blob, BlobType};
use crate::model::credential::{Credential, CredentialStateEnum, UpdateCredentialRequest};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::organisation::Organisation;
use crate::proto::oauth_client::OAuthClientProvider;
use crate::proto::transaction_manager::IsolationLevel;
use crate::provider::blob_storage::BlobStorage;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, Features};
use crate::provider::issuance_protocol::model::{CredentialWithBlob, InvitationResponseEnum};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::interaction_data_to_accepted_key_storage_security;
use crate::provider::issuance_protocol::{
    self, HolderBindingInput, IssuanceProtocol, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::service::error::MissingProviderError;
use crate::validator::ecosystem::{
    SelectionRole, commit_selected_ecosystem, resolve_ecosystem,
    validate_ecosystem_selection_allow_not_set, validate_ecosystem_step,
};
use crate::validator::key_security::match_key_security_level;
use crate::validator::{throw_if_credential_state_not_eq, throw_if_org_id_not_matching_session};

const STATE: &str = "state";
const AUTHORIZATION_CODE: &str = "code";

impl SSIHolderService {
    pub async fn accept_credential(
        &self,
        interaction_id: InteractionId,
        did_id: Option<DidId>,
        identifier_id: Option<IdentifierId>,
        key_id: Option<KeyId>,
        tx_code: Option<String>,
    ) -> Result<CredentialId, HolderServiceError> {
        let identifier = match (did_id, identifier_id) {
            (Some(did_id), None) => Some(
                self.identifier_repository
                    .get_from_did_id(did_id)
                    .await
                    .error_while("getting identifier")?
                    .ok_or(HolderServiceError::MissingDid(did_id))?,
            ),
            (None, Some(identifier_id)) => Some(
                self.identifier_repository
                    .get(identifier_id)
                    .await
                    .error_while("getting identifier")?,
            ),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(HolderServiceError::InvalidIdentifierInput(
                    "Both didId and identifierId specified".to_string(),
                ));
            }
        };

        let holder_binding_input = if let Some(identifier) = identifier {
            throw_if_org_id_not_matching_session(
                &identifier.organisation.id(),
                &*self.session_provider,
            )
            .error_while("checking session")?;

            let key = select_holder_key(&identifier, key_id).await?;
            Some(HolderBindingInput { identifier, key })
        } else {
            None
        };

        let credential_id = self
            .accept_credential_final1(interaction_id, holder_binding_input, tx_code)
            .await?;

        tracing::info!(
            "Accepted issuance of credential {credential_id} for interaction {interaction_id}"
        );
        Ok(credential_id)
    }

    /// specific handling for the final-1 protocol, credential gets created after issued
    async fn accept_credential_final1(
        &self,
        interaction_id: InteractionId,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<CredentialId, HolderServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("getting interaction")?;
        throw_if_org_id_not_matching_session(
            interaction.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking interaction organisation")?;

        if interaction.interaction_type != InteractionType::Issuance {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let data: issuance_protocol::openid4vci_final1_0::model::HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        if let Some(holder_binding) = &holder_binding
            && let Some(accepted_security_levels) =
                interaction_data_to_accepted_key_storage_security(&data)
        {
            match_key_security_level(
                &holder_binding.key.storage_type,
                &accepted_security_levels,
                &*self.key_security_level_provider,
            )
            .error_while("matching key security")?;
        }

        let format_type = match data.format.as_str() {
            "jwt_vc_json" => FormatType::Jwt,
            "dc+sd-jwt" => FormatType::SdJwtVc,
            "vc+sd-jwt" => FormatType::SdJwt,
            "mso_mdoc" => FormatType::Mdoc,
            "ldp_vc" => {
                if data
                    .credential_signing_alg_values_supported
                    .is_some_and(|values| {
                        values
                            .iter()
                            .any(|v| matches!(v, SigningAlgValue::String(alg) if alg == "ES256"))
                    })
                {
                    FormatType::JsonLdClassic
                } else {
                    FormatType::JsonLdBbsPlus
                }
            }
            _ => {
                return Err(HolderServiceError::MappingError(format!(
                    "Unknown format: {}",
                    data.format
                )));
            }
        };

        let (_, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or(MissingProviderError::FormatterType(format_type))
            .error_while("getting formatter")?;

        if let Some(holder_binding) = &holder_binding {
            validate_holder_capabilities(
                &self.config,
                holder_binding,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )
            .await?;
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let mut issuer_response = protocol
            .holder_accept_credential(interaction.clone(), holder_binding, tx_code)
            .await
            .error_while("accepting credential")?;

        // either the main credential blob or a batch item
        let serialized = issuer_response
            .main_credential
            .serialized
            .as_ref()
            .or(issuer_response
                .batch_items
                .first()
                .and_then(|item| item.serialized.as_ref()))
            .ok_or(HolderServiceError::MappingError(
                "missing serialized credential".to_string(),
            ))?
            .to_owned();

        // the credential is the last artifact of the issuance, so the ecosystem is final here
        let ecosystem = resolve_ecosystem(
            interaction.id,
            &ProtocolArtifact::HolderIssuanceCredential {
                credential: Cow::Borrowed(&issuer_response.main_credential.credential),
                serialized,
                credential_configuration_id: data.credential_configuration_id,
            },
            self.interaction_repository.as_ref(),
            self.ecosystem_provider.as_ref(),
            SelectionRole::Holder,
        )
        .await
        .error_while("resolving ecosystem")?;

        issuer_response.main_credential.credential.ecosystem = ecosystem.to_owned();
        for item in &mut issuer_response.batch_items {
            item.credential.ecosystem = ecosystem.to_owned();
        }

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let main_credential_id = issuer_response.main_credential.credential.id;
        self.transaction_manager
            .tx_with_config(
                async {
                    self.create_credential(
                        issuer_response.main_credential,
                        db_blob_storage.as_ref(),
                    )
                    .await?;
                    for batch_item in issuer_response.batch_items {
                        self.create_credential(batch_item, db_blob_storage.as_ref())
                            .await?;
                    }
                    Ok::<_, HolderServiceError>(())
                }
                .boxed(),
                // `CredentialRepository::create_credential` opens a READ COMMITTED
                // transaction to avoid InnoDB gap-lock deadlocks (ONES-54). Nesting
                // requires the enclosing transaction to use the same isolation level.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating credentials")??;
        Ok(main_credential_id)
    }

    async fn create_credential(
        &self,
        credential: CredentialWithBlob,
        db_blob_storage: &dyn BlobStorage,
    ) -> Result<(), HolderServiceError> {
        let CredentialWithBlob {
            credential,
            serialized,
        } = credential;

        let credential_blob_id = if let Some(token) = serialized {
            let blob = Blob::new(token.as_ref(), BlobType::Credential);
            let blob_id = blob.id;
            db_blob_storage
                .create(blob)
                .await
                .error_while("creating credential blob")?;
            Some(blob_id)
        } else {
            None
        };

        self.credential_repository
            .create_credential(Credential {
                state: CredentialStateEnum::Accepted,
                credential_blob_id,
                ..credential
            })
            .await
            .error_while("creating credential")?;
        Ok(())
    }

    pub async fn refresh_credentials(
        &self,
        interaction_id: InteractionId,
    ) -> Result<Vec<CredentialId>, HolderServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .map_err(|error| match error {
                crate::repository::error::DataLayerError::EntityNotFound { .. } => {
                    HolderServiceError::MissingCredentialsForInteraction(interaction_id)
                }
                error => error.error_while("getting interaction").into(),
            })?;
        throw_if_org_id_not_matching_session(
            interaction.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking interaction organisation")?;

        if interaction.interaction_type != InteractionType::Issuance {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let data: issuance_protocol::openid4vci_final1_0::model::HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        if data.batch_size.is_none() || data.refresh_token.is_none() {
            tracing::debug!(
                "Interaction batch: {}, refresh_token: {}",
                data.batch_size.is_some(),
                data.refresh_token.is_some()
            );
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                interaction_id,
            ));
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let credential_ids: Vec<_> = protocol
            .holder_refresh_credential(&interaction, None)
            .await
            .error_while("refreshing credential batch")?
            .into_iter()
            .map(|c| c.id)
            .collect();

        if let Some(ecosystem_id) = &interaction.ecosystem {
            let ecosystem = self.ecosystem_provider.get(ecosystem_id)?;

            let main_credential = self
                .credential_repository
                .get_credentials_by_interaction_id(&interaction_id)
                .await
                .error_while("getting credential")?
                .into_iter()
                .next()
                .ok_or(HolderServiceError::MappingError(
                    "Missing main credential".to_string(),
                ))?;

            // pick one issued credential to check issuer (the protocol makes sure the individual items have consistent issuer)
            let new_batch_item = self
                .credential_repository
                .get_credential(
                    credential_ids
                        .first()
                        .ok_or(HolderServiceError::MappingError("empty batch".to_string()))?,
                )
                .await
                .error_while("getting batch credential")?;

            let db_blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            let blob = db_blob_storage
                .get(
                    &new_batch_item
                        .credential_blob_id
                        .ok_or(HolderServiceError::MappingError("missing blob".to_string()))?,
                )
                .await
                .error_while("getting batch credential blob")?
                .ok_or(HolderServiceError::MappingError("missing blob".to_string()))?;

            let serialized = String::from_utf8(blob.value)
                .map_err(|e| HolderServiceError::MappingError(e.to_string()))?
                .into();

            ecosystem
                .validate_interaction(
                    &ProtocolArtifact::HolderIssuanceCredential {
                        credential: Cow::Owned(main_credential),
                        serialized,
                        credential_configuration_id: data.credential_configuration_id,
                    },
                    &interaction,
                )
                .await
                .error_while("validating ecosystem")?;
        }

        tracing::info!(
            "Batch issued, new credentials {credential_ids:?} for interaction {interaction_id}"
        );
        Ok(credential_ids)
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
    ) -> Result<(), HolderServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(interaction_id)
            .await
            .error_while("getting credentials")?;

        if credentials.is_empty() {
            return Err(HolderServiceError::MissingCredentialsForInteraction(
                *interaction_id,
            ));
        }
        validate_credentials_match_session_organisation(&credentials, &*self.session_provider)
            .await?;

        let credential_protocol_pairs = credentials
            .into_iter()
            .map(|credential| {
                throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Accepted)
                    .error_while("checking credential state")?;

                let protocol = self
                    .issuance_protocol_provider
                    .get_protocol(&credential.protocol)?;

                if !protocol
                    .get_capabilities()
                    .features
                    .contains(&Features::SupportsRejection)
                {
                    return Err(HolderServiceError::RejectionNotSupported);
                }

                Ok((credential, protocol))
            })
            .collect::<Result<Vec<_>, HolderServiceError>>()?;

        let mut result: Result<(), HolderServiceError> = Ok(());
        for (credential, protocol) in credential_protocol_pairs {
            if let Err(err) = self.reject_single_credential(credential, &*protocol).await {
                result = Err(err);
            };
        }

        result
    }

    async fn reject_single_credential(
        &self,
        credential: Credential,
        protocol: &dyn IssuanceProtocol,
    ) -> Result<(), HolderServiceError> {
        let credential_id = credential.id;

        // Reject locally first; the issuer notification is informational and
        // must not break the rejection.
        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Rejected),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        if let Err(error) = protocol.holder_reject_credential(credential).await {
            tracing::warn!(
                "Failed to notify the issuer about rejected credential {credential_id}: {error}"
            );
        }

        Ok(())
    }

    /// Settle the ecosystem of an interaction the protocol has just created: a user selection is
    /// a commitment and is recorded as one, so that every later step runs under it. Without a
    /// selection, autodetection starts narrowing the candidates here.
    async fn start_ecosystem(
        &self,
        interaction_id: InteractionId,
        artifact: &ProtocolArtifact<'_>,
        user_selected_ecosystem: Option<&EcosystemId>,
    ) -> Result<(), HolderServiceError> {
        match user_selected_ecosystem {
            Some(selection) => commit_selected_ecosystem(
                interaction_id,
                artifact,
                selection,
                self.interaction_repository.as_ref(),
                self.ecosystem_provider.as_ref(),
            )
            .await
            .error_while("committing selected ecosystem")?,
            None => validate_ecosystem_step(
                interaction_id,
                artifact,
                self.interaction_repository.as_ref(),
                self.ecosystem_provider.as_ref(),
                SelectionRole::Holder,
            )
            .await
            .error_while("narrowing ecosystem candidates")?,
        }

        Ok(())
    }

    pub(super) async fn handle_issuance_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        exchange: String,
        issuance_protocol: Arc<dyn IssuanceProtocol>,
        redirect_uri: Option<String>,
        user_selected_ecosystem: Option<EcosystemId>,
    ) -> Result<HandleInvitationResultDTO, HolderServiceError> {
        let result = issuance_protocol
            .holder_handle_invitation(url, organisation, redirect_uri)
            .await
            .error_while("handling invitation")?;

        match result {
            InvitationResponseEnum::Credential {
                interaction_id,
                tx_code,
                key_storage_security,
                key_algorithms,
                requires_wallet_instance_attestation,
                ecosystem_artifact,
            } => {
                self.start_ecosystem(
                    interaction_id,
                    &ecosystem_artifact,
                    user_selected_ecosystem.as_ref(),
                )
                .await?;

                Ok(HandleInvitationResultDTO::Credential {
                    interaction_id,
                    tx_code,
                    key_storage_security_levels: key_storage_security,
                    key_algorithms,
                    protocol: exchange,
                    requires_wallet_instance_attestation,
                    ecosystem: user_selected_ecosystem,
                })
            }
            InvitationResponseEnum::AuthorizationFlow {
                organisation_id,
                issuer,
                client_id,
                redirect_uri,
                authorization_details,
                scope,
                issuer_state,
                authorization_server,
                ecosystem_artifact,
            } => {
                let InitiateIssuanceResponseDTO {
                    interaction_id,
                    url,
                } = self
                    .initiate_issuance(InitiateIssuanceRequestDTO {
                        organisation_id,
                        protocol: exchange.to_owned(),
                        issuer,
                        client_id,
                        redirect_uri,
                        scope,
                        authorization_details,
                        issuer_state,
                        authorization_server,
                        ecosystem: user_selected_ecosystem.clone(),
                    })
                    .await?;

                // `initiate_issuance` created the interaction carrying any user selection
                validate_ecosystem_step(
                    interaction_id,
                    &ecosystem_artifact,
                    self.interaction_repository.as_ref(),
                    self.ecosystem_provider.as_ref(),
                    SelectionRole::Holder,
                )
                .await
                .error_while("validating ecosystem")?;

                Ok(HandleInvitationResultDTO::AuthorizationCodeFlow {
                    interaction_id,
                    authorization_code_flow_url: url,
                    protocol: exchange,
                    ecosystem: user_selected_ecosystem,
                })
            }
        }
    }

    pub async fn initiate_issuance(
        &self,
        request: InitiateIssuanceRequestDTO,
    ) -> Result<InitiateIssuanceResponseDTO, HolderServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        validate_initiate_issuance_request(&request, &self.config)?;

        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        let authorization_server = request
            .authorization_server
            .as_ref()
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3-2.2
            // ... If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server
            .unwrap_or(&request.issuer);

        let authorization_server = Url::parse(authorization_server).map_err(|e| {
            HolderServiceError::InvalidInput(format!("Invalid authorization server: {e}"))
        })?;

        let interaction_id: InteractionId = Uuid::new_v4().into();
        let authorization_request = AuthorizationRequest::builder()
            .client_id(request.client_id.clone())
            .maybe_scope(request.scope.as_ref().map(|s| s.join(" ")))
            .state(interaction_id.to_string())
            .maybe_redirect_uri(request.redirect_uri.clone())
            .maybe_authorization_details(
                request
                    .authorization_details
                    .as_ref()
                    .map(|ad| serde_json::json!(ad).to_string()),
            )
            .maybe_issuer_state(request.issuer_state.clone())
            .build();

        let authorization_response = self
            .client
            .oauth_client()
            .initiate_authorization_code_flow(authorization_server, authorization_request)
            .await
            .error_while("initiating authorization code flow")?;

        validate_ecosystem_selection_allow_not_set(
            request.ecosystem.as_ref(),
            &organisation,
            self.ecosystem_provider.as_ref(),
        )
        .error_while("validating ecosystem")?;

        let ecosystem = request.ecosystem.clone();
        let interaction_data = OpenIDAuthorizationCodeFlowInteractionData {
            request,
            code_verifier: authorization_response.code_verifier,
        };
        // store request parameters inside interaction
        let data = serialize_interaction_data(&interaction_data)
            .error_while("storing interaction data")?;

        let now = crate::clock::now_utc();
        self.interaction_repository
            .create_interaction(Interaction {
                id: interaction_id,
                created_date: now,
                last_modified: now,
                data: Some(data),
                organisation: organisation.into(),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
                expires_at: None,
                ecosystem,
                ecosystem_data: Default::default(),
            })
            .await
            .error_while("creating interaction")?;

        tracing::info!(
            "Initiated authorization code flow for credential issuance, created interaction {interaction_id}"
        );
        Ok(InitiateIssuanceResponseDTO {
            interaction_id,
            url: authorization_response.url.to_string(),
        })
    }

    pub async fn continue_issuance(
        &self,
        url: impl AsRef<str>,
    ) -> Result<ContinueIssuanceResponseDTO, HolderServiceError> {
        let url = Url::parse(url.as_ref()).map_err(|error| {
            HolderServiceError::InvalidInput(format!(
                "Continuation URL has invalid format: {error}"
            ))
        })?;

        let (_, state) = url.query_pairs().find(|(key, _)| key == STATE).ok_or(
            HolderServiceError::InvalidInput(
                "Continuation URL state parameter not specified".to_string(),
            ),
        )?;

        let (_, authorization_code) = url
            .query_pairs()
            .find(|(key, _)| key == AUTHORIZATION_CODE)
            .ok_or(HolderServiceError::InvalidInput(
                "Continuation URL authorization_code parameter not specified".to_string(),
            ))?;

        let interaction_id = Uuid::parse_str(state.as_ref())
            .map_err(|_| {
                HolderServiceError::InvalidInput(
                    "Continuation URL state parameter has invalid format".to_string(),
                )
            })?
            .into();

        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("getting interaction")?;

        throw_if_org_id_not_matching_session(
            interaction.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;
        let issuance: OpenIDAuthorizationCodeFlowInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("parsing holder interaction data")?;

        let organisation = interaction.organisation.as_ref().await?.to_owned();
        let user_selected_ecosystem = issuance.request.ecosystem.to_owned();

        if let (None, None) = (
            issuance.request.scope.as_ref(),
            issuance.request.authorization_details.as_ref(),
        ) {
            return Err(HolderServiceError::InvalidInput("Either `scope` or `authorization_details` has to be specified for credential issuance".to_string()));
        }

        let issuance_protocol::model::ContinueIssuanceResponseDTO {
            interaction_id,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol,
            ecosystem_artifact,
        } = self
            .issuance_protocol_provider
            .get_protocol(&issuance.request.protocol)?
            .holder_continue_issuance(
                ContinueIssuanceDTO {
                    credential_issuer: issuance.request.issuer,
                    authorization_code: authorization_code.to_string(),
                    client_id: issuance.request.client_id,
                    redirect_uri: issuance.request.redirect_uri,
                    scope: issuance.request.scope.unwrap_or_default(),
                    credential_configuration_ids: issuance
                        .request
                        .authorization_details
                        .unwrap_or_default()
                        .into_iter()
                        .map(|d| d.credential_configuration_id)
                        .collect(),
                    code_verifier: issuance.code_verifier,
                    authorization_server: issuance.request.authorization_server,
                },
                organisation,
            )
            .await
            .error_while("continuing issuance")?;

        // continuing creates a fresh interaction, so a selection made when the flow was initiated
        // has to be committed onto that one too
        self.start_ecosystem(
            interaction_id,
            &ecosystem_artifact,
            user_selected_ecosystem.as_ref(),
        )
        .await?;

        tracing::info!(
            "Processed authorization code flow result for credential issuance using interaction {interaction_id}"
        );

        Ok(ContinueIssuanceResponseDTO {
            interaction_id,
            interaction_type: InteractionType::Issuance,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol,
            ecosystem: user_selected_ecosystem,
        })
    }
}
