use std::borrow::Cow;
use std::collections::HashMap;
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
    InitiateIssuanceResponseDTO, IssuanceAcceptResponseDTO,
    OpenIDAuthorizationCodeFlowInteractionData,
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
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialStateEnum, CredentialType, UpdateCredentialRequest,
};
use crate::model::interaction::{Interaction, InteractionType};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListQuery;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::oauth_client::OAuthClientProvider;
use crate::proto::transaction_manager::IsolationLevel;
use crate::provider::blob_storage::BlobStorage;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, Features};
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::model::{
    CredentialWithBlob, InvitationResponseEnum, IssuanceAcceptResponse,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::configuration_to_accepted_key_storage_security;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::HolderCredentialConfiguration;
use crate::provider::issuance_protocol::{
    self, HolderBindingInput, IssuanceProtocol, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::service::error::MissingProviderError;
use crate::validator::ecosystem::validate_ecosystem_selection_allow_not_set;
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
    ) -> Result<IssuanceAcceptResponseDTO, HolderServiceError> {
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

        let response = self
            .accept_credential_final1(interaction_id, holder_binding_input, tx_code)
            .await?;

        tracing::info!(
            "Accepted issuance of credentials {:?} for interaction {interaction_id}",
            response.credential_ids
        );
        Ok(response)
    }

    /// specific handling for the final-1 protocol, credential gets created after issued
    async fn accept_credential_final1(
        &self,
        interaction_id: InteractionId,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<IssuanceAcceptResponseDTO, HolderServiceError> {
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

        // a configuration the holder binding does not satisfy is skipped, unless none is left
        let mut accepted_configuration_ids = vec![];
        let mut skip_error = None;
        for configuration in &data.credential_configurations {
            match self
                .validate_credential_configuration(holder_binding.as_ref(), configuration)
                .await
            {
                Ok(()) => accepted_configuration_ids
                    .push(configuration.credential_configuration_id.clone()),
                Err(error) => {
                    tracing::warn!(
                        "Skipping credential configuration {}: {error}",
                        configuration.credential_configuration_id
                    );
                    skip_error = Some(error);
                }
            }
        }
        if accepted_configuration_ids.is_empty() {
            return Err(skip_error.unwrap_or(
                HolderServiceError::MissingCredentialsForInteraction(interaction_id),
            ));
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let result = protocol
            .holder_accept_credential(
                interaction.clone(),
                holder_binding,
                tx_code,
                accepted_configuration_ids,
            )
            .await
            .error_while("accepting credential")?;

        for failure in &result.failed {
            tracing::warn!(
                "Credential configuration {} not issued: {}",
                failure.credential_configuration_id,
                failure.error
            );
        }
        if result.issued.is_empty() {
            let error = result
                .failed
                .into_iter()
                .next()
                .map(|failure| failure.error)
                .unwrap_or(IssuanceProtocolError::Failed(
                    "No credential configuration issued".to_string(),
                ));
            return Err(error.error_while("accepting credential").into());
        }
        // a single configuration offer succeeds or fails as a whole
        let partially_successful = (data.credential_configurations.len() > 1)
            .then_some(!result.failed.is_empty() || skip_error.is_some());

        // the credentials are the last artifacts of the issuance, so the ecosystem is final here
        let artifacts = result
            .issued
            .iter()
            .map(|issuer_response| {
                let issued = issuer_response
                    .batch_items
                    .first()
                    .unwrap_or(&issuer_response.main_credential);
                let serialized = issued
                    .serialized
                    .as_ref()
                    .ok_or(HolderServiceError::MappingError(
                        "missing serialized credential".to_string(),
                    ))?
                    .to_owned();
                Ok(ProtocolArtifact::HolderIssuanceCredential {
                    credential: Cow::Borrowed(&issued.credential),
                    serialized,
                    credential_configuration_id: issuer_response
                        .credential_configuration_id
                        .clone(),
                })
            })
            .collect::<Result<Vec<_>, HolderServiceError>>()?;
        let ecosystems = self
            .ecosystem_resolver
            .resolve(interaction.id, &artifacts, None)
            .await
            .error_while("resolving ecosystems")?;

        let mut issued = result.issued;
        for (issuer_response, ecosystem) in issued.iter_mut().zip(ecosystems.per_credential) {
            issuer_response
                .main_credential
                .credential
                .common_mut()
                .ecosystem = ecosystem.to_owned();
            for item in &mut issuer_response.batch_items {
                item.credential.common_mut().ecosystem = ecosystem.to_owned();
            }
        }

        let (issued, configuration_parents) = self.group_issued_credentials(issued).await?;

        let mut credential_ids = vec![];
        let mut credentials = vec![];
        for issuer_response in issued {
            credential_ids.push(issuer_response.main_credential.credential.common().id);
            // the batch parent must exist before the batch items are created
            credentials.push(issuer_response.main_credential);
            credentials.extend(issuer_response.batch_items);
        }
        let id = credential_ids.first().copied().ok_or(
            HolderServiceError::MissingCredentialsForInteraction(interaction_id),
        )?;

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        self.transaction_manager
            .tx_with_config(
                async {
                    let mut prepared = Vec::with_capacity(credentials.len());
                    for credential in credentials {
                        prepared.push(
                            self.prepare_credential(credential, db_blob_storage.as_ref())
                                .await?,
                        );
                    }
                    self.credential_repository
                        .create_credentials(prepared)
                        .await
                        .error_while("creating credentials")?;
                    if !configuration_parents.is_empty() {
                        protocol
                            .regroup_configurations(interaction_id, configuration_parents)
                            .await
                            .error_while("regrouping credential configurations")?;
                    }
                    Ok::<_, HolderServiceError>(())
                }
                .boxed(),
                // `CredentialRepository::create_credentials` opens a READ COMMITTED
                // transaction to avoid InnoDB gap-lock deadlocks (ONES-54). Nesting
                // requires the enclosing transaction to use the same isolation level.
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating credentials")??;
        Ok(IssuanceAcceptResponseDTO {
            id,
            credential_ids,
            partially_successful,
            ecosystem_outcomes: ecosystems.outcomes,
        })
    }

    pub(super) async fn group_issued_credentials(
        &self,
        issued: Vec<IssuanceAcceptResponse>,
    ) -> Result<(Vec<IssuanceAcceptResponse>, HashMap<String, CredentialId>), HolderServiceError>
    {
        // The protocol has already decided which configurations need batch parents.
        // Preserve offer order and keep singles and different schemas/ecosystems/claims separate.
        let mut groups: Vec<IssuanceAcceptResponse> = vec![];
        let mut batch_groups = HashMap::new();
        let mut configuration_parents = HashMap::new();
        for mut response in issued {
            let credential = &response.main_credential.credential;
            if !matches!(credential, Credential::HolderBatchParent { .. }) {
                groups.push(response);
                continue;
            }
            // Parents have no claims. The protocol validates consistency within each batch,
            // so compare the first item's non-metadata claims across configurations.
            let Some(item) = response.batch_items.first() else {
                groups.push(response);
                continue;
            };
            let mut claims = vec![];
            for claim in item.credential.holder()?.data.claims.as_ref().await?.iter() {
                if !claim.schema.as_ref().await?.metadata {
                    claims.push((claim.path.clone(), claim.value.clone()));
                }
            }
            claims.sort_unstable();
            let key = (
                credential.common().schema.id(),
                credential.common().ecosystem.clone(),
                claims,
            );
            let Some(group) = batch_groups
                .get(&key)
                .and_then(|&index| groups.get_mut(index))
            else {
                batch_groups.insert(key, groups.len());
                groups.push(response);
                continue;
            };
            let parent_id = group.main_credential.credential.common().id;
            configuration_parents.insert(response.credential_configuration_id, parent_id);
            for item in &mut response.batch_items {
                match &mut item.credential {
                    Credential::IssuerBatchItem { parent, .. }
                    | Credential::HolderBatchItem { parent, .. } => {
                        *parent = Related::new(parent_id, self.credential_repository.clone());
                    }
                    _ => {
                        return Err(HolderServiceError::MappingError(
                            "expected batch item when regrouping credentials".to_string(),
                        ));
                    }
                }
            }
            group.batch_items.append(&mut response.batch_items);
        }
        Ok((groups, configuration_parents))
    }

    async fn validate_credential_configuration(
        &self,
        holder_binding: Option<&HolderBindingInput>,
        configuration: &HolderCredentialConfiguration,
    ) -> Result<(), HolderServiceError> {
        if let Some(holder_binding) = holder_binding
            && let Some(accepted_security_levels) =
                configuration_to_accepted_key_storage_security(configuration)
        {
            match_key_security_level(
                &holder_binding.key.storage_type,
                &accepted_security_levels,
                &*self.key_security_level_provider,
            )
            .error_while("matching key security")?;
        }

        let format_type = match configuration.format.as_str() {
            "jwt_vc_json" => FormatType::Jwt,
            "dc+sd-jwt" => FormatType::SdJwtVc,
            "vc+sd-jwt" => FormatType::SdJwt,
            "mso_mdoc" => FormatType::Mdoc,
            "ldp_vc" => {
                if configuration
                    .credential_signing_alg_values_supported
                    .as_ref()
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
                    configuration.format
                )));
            }
        };

        let (_, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or(MissingProviderError::FormatterType(format_type))
            .error_while("getting formatter")?;

        if let Some(holder_binding) = holder_binding {
            validate_holder_capabilities(
                &self.config,
                holder_binding,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )
            .await?;
        }

        Ok(())
    }

    async fn prepare_credential(
        &self,
        credential: CredentialWithBlob,
        db_blob_storage: &dyn BlobStorage,
    ) -> Result<Credential, HolderServiceError> {
        let CredentialWithBlob {
            mut credential,
            serialized,
        } = credential;

        credential.common_mut().state = CredentialStateEnum::Accepted;
        if matches!(credential, Credential::HolderBatchParent { .. }) && serialized.is_none() {
            return Ok(credential);
        }

        let holder = credential.holder_mut()?;
        holder.data.credential_blob_id = if let Some(token) = serialized {
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

        Ok(credential)
    }

    pub async fn refresh_credentials(
        &self,
        interaction_id: InteractionId,
    ) -> Result<Vec<CredentialId>, HolderServiceError> {
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

        if data.refresh_token.is_none() {
            return Err(HolderServiceError::RefreshNotSupported);
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)?;

        let refreshed = protocol
            .holder_refresh_credential(&interaction, None)
            .await
            .error_while("refreshing credential batch")?;
        let credential_ids: Vec<_> = refreshed
            .iter()
            .flat_map(|response| &response.credentials)
            .map(|credential| credential.common().id)
            .collect();

        if interaction.ecosystem.is_some() {
            let db_blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            // Issuer consistency is checked within each configuration, not across a shared parent.
            for response in refreshed {
                let Some(batch_item) = response.credentials.first() else {
                    continue;
                };

                let batch_item = self
                    .credential_repository
                    .get_credential(&batch_item.common().id)
                    .await
                    .error_while("getting batch credential")?;
                let blob_id = batch_item
                    .holder()?
                    .data
                    .credential_blob_id
                    .ok_or(HolderServiceError::MappingError("missing blob".to_string()))?;
                let blob = db_blob_storage
                    .get(&blob_id)
                    .await
                    .error_while("getting batch credential blob")?
                    .ok_or(HolderServiceError::MappingError("missing blob".to_string()))?;
                let serialized = String::from_utf8(blob.value)
                    .map_err(|e| HolderServiceError::MappingError(e.to_string()))?
                    .into();

                self.ecosystem_resolver
                    .revalidate(
                        &interaction,
                        &[ProtocolArtifact::HolderIssuanceCredential {
                            credential: Cow::Owned(batch_item),
                            serialized,
                            credential_configuration_id: response.credential_configuration_id,
                        }],
                    )
                    .await
                    .error_while("validating ecosystem")?;
            }
        }

        tracing::info!(
            "Batch issued, new credentials {credential_ids:?} for interaction {interaction_id}"
        );
        Ok(credential_ids)
    }

    pub async fn reject_credential(
        &self,
        interaction_id: &InteractionId,
        credential_ids: Option<Vec<CredentialId>>,
    ) -> Result<(), HolderServiceError> {
        let mut credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(interaction_id)
            .await
            .error_while("getting credentials")?;

        // Items inherit the interaction from their parent. Limit the lookup to this
        // interaction's parents, and let an explicitly selected parent cover its items.
        if let Some(ids) = &credential_ids {
            let parent_ids: Vec<_> = credentials
                .iter()
                .filter(|credential| {
                    matches!(
                        credential,
                        Credential::IssuerBatchParent { .. } | Credential::HolderBatchParent { .. }
                    ) && !ids.contains(&credential.common().id)
                })
                .map(|credential| credential.common().id)
                .collect();
            if !parent_ids.is_empty() {
                credentials.extend(
                    self.credential_repository
                        .get_credential_list(ListQuery {
                            include_count: false,
                            filtering: Some(
                                CredentialFilterValue::ParentCredentials(parent_ids).condition()
                                    & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                                    & CredentialFilterValue::CredentialIds(ids.clone()),
                            ),
                            ..Default::default()
                        })
                        .await
                        .error_while("getting selected batch items")?
                        .values,
                );
            }
        }
        let credentials: Vec<_> = credentials
            .into_iter()
            .filter(|credential| {
                credential_ids
                    .as_ref()
                    .is_none_or(|ids| ids.contains(&credential.common().id))
            })
            .collect();

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
                    .get_protocol(&credential.common().protocol)?;

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
            if let Err(err) = self.reject_offered_credential(credential, &*protocol).await {
                result = Err(err);
            };
        }

        result
    }

    async fn reject_offered_credential(
        &self,
        credential: Credential,
        protocol: &dyn IssuanceProtocol,
    ) -> Result<(), HolderServiceError> {
        // Reject locally first; the issuer notification is informational and
        // must not break the rejection.
        for credential_id in self.credential_and_batch_item_ids(&credential).await? {
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
        }

        let credential_id = credential.common().id;
        if let Err(error) = protocol.holder_reject_credential(credential).await {
            tracing::warn!(
                "Failed to notify the issuer about rejected credential {credential_id}: {error}"
            );
        }

        Ok(())
    }

    // the items of a batch follow their parent
    async fn credential_and_batch_item_ids(
        &self,
        credential: &Credential,
    ) -> Result<Vec<CredentialId>, HolderServiceError> {
        let batch_items = match credential {
            Credential::IssuerBatchParent { .. } | Credential::HolderBatchParent { .. } => {
                self.credential_repository
                    .get_credential_list(ListQuery {
                        include_count: false,
                        filtering: Some(
                            CredentialFilterValue::ParentCredential(credential.common().id)
                                .condition(),
                        ),
                        ..Default::default()
                    })
                    .await
                    .error_while("getting batch items")?
                    .values
            }
            _ => vec![],
        };
        Ok(std::iter::once(credential.common().id)
            .chain(batch_items.into_iter().map(|item| item.common().id))
            .collect())
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
                let ecosystem_outcomes = self
                    .ecosystem_resolver
                    .resolve(
                        interaction_id,
                        &[ecosystem_artifact],
                        user_selected_ecosystem.as_ref(),
                    )
                    .await
                    .error_while("resolving ecosystem")?
                    .outcomes;

                Ok(HandleInvitationResultDTO::Credential {
                    interaction_id,
                    tx_code,
                    key_storage_security_levels: key_storage_security,
                    key_algorithms,
                    protocol: exchange,
                    requires_wallet_instance_attestation,
                    ecosystem: user_selected_ecosystem,
                    ecosystem_outcomes,
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
                let ecosystem_outcomes = self
                    .ecosystem_resolver
                    .resolve(interaction_id, &[ecosystem_artifact], None)
                    .await
                    .error_while("resolving ecosystem")?
                    .outcomes;

                Ok(HandleInvitationResultDTO::AuthorizationCodeFlow {
                    interaction_id,
                    authorization_code_flow_url: url,
                    protocol: exchange,
                    ecosystem: user_selected_ecosystem,
                    ecosystem_outcomes,
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
        self.ecosystem_resolver
            .resolve(
                interaction_id,
                &[ecosystem_artifact],
                user_selected_ecosystem.as_ref(),
            )
            .await
            .error_while("resolving ecosystem")?;

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
