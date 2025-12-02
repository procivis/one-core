use std::sync::Arc;

use shared_types::{CredentialId, DidId, HolderWalletUnitId, IdentifierId, KeyId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::SSIHolderService;
use super::dto::{
    ContinueIssuanceResponseDTO, HandleInvitationResultDTO, InitiateIssuanceRequestDTO,
    InitiateIssuanceResponseDTO, OpenIDAuthorizationCodeFlowInteractionData,
};
use super::validator::{
    validate_credentials_match_session_organisation, validate_holder_capabilities,
    validate_initiate_issuance_request,
};
use crate::config::core_config::FormatType;
use crate::mapper::value_to_model_claims;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{DidRelations, KeyFilter, KeyRole};
use crate::model::identifier::{IdentifierRelations, IdentifierType};
use crate::model::interaction::{
    Interaction, InteractionId, InteractionRelations, InteractionType,
};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::proto::oauth_client::{OAuthAuthorizationRequest, OAuthClientProvider};
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::dto::{ContinueIssuanceDTO, Features};
use crate::provider::issuance_protocol::error::{
    IssuanceProtocolError, OpenID4VCIError, OpenIDIssuanceError,
};
use crate::provider::issuance_protocol::model::{
    InvitationResponseEnum, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper::interaction_data_to_accepted_key_storage_security;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::CredentialSigningAlgValue;
use crate::provider::issuance_protocol::{
    self, HolderBindingInput, IssuanceProtocol, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::service::error::ServiceError::BusinessLogic;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::storage_proxy::StorageAccess;
use crate::validator::key_security::{
    match_key_security_level, validate_key_storage_supports_security_requirement,
};
use crate::validator::{
    throw_if_credential_state_not_eq, throw_if_org_not_matching_session,
    throw_if_org_relation_not_matching_session,
};

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
        holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<CredentialId, ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                &interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    ..Default::default()
                },
            )
            .await?;

        let identifier = match (did_id, identifier_id) {
            (Some(did_id), None) => Some(
                self.identifier_repository
                    .get_from_did_id(
                        did_id,
                        &IdentifierRelations {
                            organisation: Some(OrganisationRelations::default()),
                            did: Some(DidRelations {
                                keys: Some(Default::default()),
                                ..Default::default()
                            }),
                            key: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(ServiceError::from(ValidationError::DidNotFound))?,
            ),
            (None, Some(identifier_id)) => Some(
                self.identifier_repository
                    .get(
                        identifier_id,
                        &IdentifierRelations {
                            organisation: Some(OrganisationRelations::default()),
                            did: Some(DidRelations {
                                keys: Some(Default::default()),
                                ..Default::default()
                            }),
                            key: Some(Default::default()),
                            ..Default::default()
                        },
                    )
                    .await?
                    .ok_or(ServiceError::from(EntityNotFoundError::Identifier(
                        identifier_id,
                    )))?,
            ),
            (None, None) => None,
            (Some(_), Some(_)) => {
                return Err(BusinessLogicError::InvalidHolderIdentifier(
                    "Both didId and identifierId specified".to_string(),
                )
                .into());
            }
        };

        let holder_binding_input = if let Some(identifier) = identifier {
            throw_if_org_relation_not_matching_session(
                identifier.organisation.as_ref(),
                &*self.session_provider,
            )?;

            let key = match identifier.r#type {
                IdentifierType::Key => {
                    let key = identifier.key.to_owned().ok_or(ServiceError::MappingError(
                        "Missing identifier key".to_string(),
                    ))?;

                    if let Some(key_id) = key_id
                        && key_id != key.id
                    {
                        return Err(ValidationError::InvalidKey(
                            "Mismatch keyId of selected identifier".to_string(),
                        )
                        .into());
                    }
                    key
                }
                IdentifierType::Did => {
                    let did = identifier.did.to_owned().ok_or(ServiceError::MappingError(
                        "Missing identifier did".to_string(),
                    ))?;

                    let key_filter = KeyFilter::role_filter(KeyRole::Authentication);
                    let selected_key = match key_id {
                        Some(key_id) => did
                            .find_key(&key_id, &key_filter)?
                            .ok_or(ValidationError::KeyNotFound)?,
                        None => did.find_first_matching_key(&key_filter)?.ok_or(
                            ValidationError::InvalidKey(
                                "No key with role authentication available".to_string(),
                            ),
                        )?,
                    };
                    selected_key.key.to_owned()
                }
                _ => {
                    return Err(BusinessLogic(
                        BusinessLogicError::IncompatibleHolderIdentifier,
                    ));
                }
            };

            Some(HolderBindingInput { identifier, key })
        } else {
            None
        };

        if credentials.is_empty() {
            return self
                .accept_credential_final1(
                    interaction_id,
                    holder_binding_input,
                    tx_code,
                    holder_wallet_unit_id,
                )
                .await;
        }

        validate_credentials_match_session_organisation(&credentials, &*self.session_provider)?;

        // Errors are gathered into vec, so we can try to accept all credentials.
        let mut errors = vec![];

        let mut credential_id = None;
        for credential in credentials {
            credential_id = Some(credential.id);
            if let Err(error) = self
                .accept_and_save_credential_draft13(
                    &credential,
                    holder_binding_input.clone(),
                    tx_code.clone(),
                )
                .await
            {
                tracing::error!("Failed to accept credential: {error}");

                let _result = self
                    .credential_repository
                    .update_credential(
                        credential.id,
                        UpdateCredentialRequest {
                            state: Some(CredentialStateEnum::Error),
                            ..Default::default()
                        },
                    )
                    .await;

                errors.push(error);
            }
        }

        if let Some(error) = errors.into_iter().next() {
            return Err(error);
        }

        Ok(credential_id.ok_or(IssuanceProtocolError::Failed(
            "No credential issued".to_string(),
        ))?)
    }

    /// specific handling for the final-1 protocol, credential gets created after issued
    async fn accept_credential_final1(
        &self,
        interaction_id: InteractionId,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
        holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<CredentialId, ServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                None,
            )
            .await?
            .ok_or(BusinessLogicError::MissingCredentialsForInteraction { interaction_id })?;

        if interaction.interaction_type != InteractionType::Issuance {
            return Err(
                BusinessLogicError::MissingCredentialsForInteraction { interaction_id }.into(),
            );
        }

        let data: issuance_protocol::openid4vci_final1_0::model::HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        if let Some(holder_binding) = &holder_binding
            && let Some(accepted_security_levels) =
                interaction_data_to_accepted_key_storage_security(&data)
        {
            match_key_security_level(
                &holder_binding.key.storage_type,
                &accepted_security_levels,
                &*self.key_security_level_provider,
            )?;
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
                            .any(|v| matches!(v, CredentialSigningAlgValue::String(alg) if alg == "ES256"))
                    })
                {
                    FormatType::JsonLdClassic
                } else {
                    FormatType::JsonLdBbsPlus
                }
            }
            _ => {
                return Err(OpenIDIssuanceError::OpenID4VCI(
                    OpenID4VCIError::UnsupportedCredentialFormat,
                )
                .into());
            }
        };

        let format = format_type.to_string();
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(format),
            ))?;

        if let Some(holder_binding) = &holder_binding {
            validate_holder_capabilities(
                &self.config,
                holder_binding,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )?;
        }

        let protocol = self
            .issuance_protocol_provider
            .get_protocol(&data.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(data.protocol))?;

        let issuer_response = protocol
            .holder_accept_credential(
                interaction,
                holder_binding,
                &self.storage_proxy(),
                tx_code,
                holder_wallet_unit_id,
            )
            .await?;

        let credential = issuer_response
            .create_credential
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Credential missing".to_string(),
            ))?
            .to_owned();

        let issuer_response = self.resolve_update_issuer_response(issuer_response).await?;

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let blob = Blob::new(
            issuer_response.credential.as_bytes().to_vec(),
            BlobType::Credential,
        );
        let blob_id = blob.id;
        db_blob_storage.create(blob.clone()).await?;

        let credential_id = self
            .credential_repository
            .create_credential(Credential {
                state: CredentialStateEnum::Accepted,
                credential_blob_id: Some(blob_id),
                ..credential
            })
            .await?;

        Ok(credential_id)
    }

    async fn accept_and_save_credential_draft13(
        &self,
        credential: &Credential,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        throw_if_credential_state_not_eq(credential, CredentialStateEnum::Pending)?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        if let Some(holder_binding) = &holder_binding {
            validate_key_storage_supports_security_requirement(
                &holder_binding.key.storage_type,
                &schema.key_storage_security,
                &*self.key_security_level_provider,
            )?;
        }

        let format = &schema.format;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(format.to_owned()),
            ))?;

        if let Some(holder_binding) = &holder_binding {
            validate_holder_capabilities(
                &self.config,
                holder_binding,
                &formatter.get_capabilities(),
                self.key_algorithm_provider.as_ref(),
            )?;
        }

        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let issuer_response = self
            .issuance_protocol_provider
            .get_protocol(&credential.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                credential.protocol.clone(),
            ))?
            .holder_accept_credential(
                interaction,
                holder_binding,
                &self.storage_proxy(),
                tx_code,
                None,
            )
            .await?;

        let issuer_response = self.resolve_update_issuer_response(issuer_response).await?;
        let claims = self
            .extract_claims(&credential.id, &issuer_response.credential, schema)
            .await?;

        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))?;

        let blob_id = match credential.credential_blob_id {
            None => {
                let blob = Blob::new(
                    issuer_response.credential.as_bytes().to_vec(),
                    BlobType::Credential,
                );
                db_blob_storage.create(blob.clone()).await?;
                blob.id
            }
            Some(blob_id) => {
                db_blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(issuer_response.credential.as_bytes().to_vec()),
                        },
                    )
                    .await?;
                blob_id
            }
        };

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Accepted),
                    claims: Some(claims),
                    credential_blob_id: Some(blob_id),
                    ..Default::default()
                },
            )
            .await?;

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
            .get_credential_formatter(credential_format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(credential_format.to_owned()),
            ))?;

        let credential = formatter
            .extract_credentials_unverified(credential, Some(schema))
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

        for (key, value) in credential.claims.claims {
            let claim_schema = claim_schemas
                .iter()
                .find(|claim_schema| claim_schema.schema.key == key);
            let Some(claim_schema) = claim_schema else {
                // Legacy compatibility shim: extra metadata claims are allowed, if not in the
                // schema they are also not stored.
                if value.metadata {
                    continue;
                }
                return Err(BusinessLogic(BusinessLogicError::MissingClaimSchemas));
            };

            collected_claims.extend(value_to_model_claims(
                *credential_id,
                claim_schemas,
                value,
                now,
                &claim_schema.schema,
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
                    interaction: Some(InteractionRelations::default()),
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
        validate_credentials_match_session_organisation(&credentials, &*self.session_provider)?;

        let credential_protocol_pairs = credentials
            .into_iter()
            .map(|credential| {
                throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Accepted)?;

                let protocol = self
                    .issuance_protocol_provider
                    .get_protocol(&credential.protocol)
                    .ok_or(MissingProviderError::ExchangeProtocol(
                        credential.protocol.clone(),
                    ))?;

                if !protocol
                    .get_capabilities()
                    .features
                    .contains(&Features::SupportsRejection)
                {
                    return Err(BusinessLogicError::RejectionNotSupported.into());
                }

                Ok((credential, protocol))
            })
            .collect::<Result<Vec<_>, ServiceError>>()?;

        let storage_proxy = self.storage_proxy();
        let mut result: Result<(), ServiceError> = Ok(());
        for (credential, protocol) in credential_protocol_pairs {
            if let Err(err) = self
                .reject_single_credential(credential, &*protocol, &storage_proxy)
                .await
            {
                result = Err(err);
            };
        }

        result
    }

    async fn reject_single_credential(
        &self,
        credential: Credential,
        protocol: &dyn IssuanceProtocol,
        storage_access: &StorageAccess,
    ) -> Result<(), ServiceError> {
        let credential_id = credential.id;
        protocol
            .holder_reject_credential(credential, storage_access)
            .await?;

        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Rejected),
                    ..Default::default()
                },
            )
            .await?;

        Ok(())
    }

    pub(super) async fn handle_issuance_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        exchange: String,
        issuance_protocol: Arc<dyn IssuanceProtocol>,
        redirect_uri: Option<String>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        let result = issuance_protocol
            .holder_handle_invitation(url, organisation, &self.storage_proxy(), redirect_uri)
            .await?;

        match result {
            InvitationResponseEnum::Credential {
                interaction_id,
                tx_code,
                key_storage_security,
                key_algorithms,
            } => Ok(HandleInvitationResultDTO::Credential {
                interaction_id,
                tx_code,
                key_storage_security_levels: key_storage_security,
                key_algorithms,
            }),
            InvitationResponseEnum::AuthorizationFlow {
                organisation_id,
                issuer,
                client_id,
                redirect_uri,
                authorization_details,
                issuer_state,
                authorization_server,
            } => {
                let InitiateIssuanceResponseDTO {
                    interaction_id,
                    url,
                } = self
                    .initiate_issuance(InitiateIssuanceRequestDTO {
                        organisation_id,
                        protocol: exchange,
                        issuer,
                        client_id,
                        redirect_uri,
                        scope: None,
                        authorization_details,
                        issuer_state,
                        authorization_server,
                    })
                    .await?;

                Ok(HandleInvitationResultDTO::AuthorizationCodeFlow {
                    interaction_id,
                    authorization_code_flow_url: url,
                })
            }
        }
    }

    async fn resolve_update_issuer_response(
        &self,
        update_response: UpdateResponse,
    ) -> Result<SubmitIssuerResponse, ServiceError> {
        if let Some(create_did) = update_response.create_did {
            self.did_repository.create_did(create_did).await?;
        }
        if let Some(create_key) = update_response.create_key {
            self.key_repository.create_key(create_key).await?;
        }
        if let Some(create_identifier) = update_response.create_identifier {
            self.identifier_repository.create(create_identifier).await?;
        }
        if let Some(certificate) = update_response.create_certificate {
            self.certificate_repository.create(certificate).await?;
        }
        if let Some(create_credential_schema) = update_response.create_credential_schema {
            self.credential_schema_importer
                .import_credential_schema(create_credential_schema)
                .await?;
        }
        if let Some(update_credential_schema) = update_response.update_credential_schema {
            self.credential_schema_repository
                .update_credential_schema(update_credential_schema)
                .await?;
        }
        if let Some((credential_id, update_credential)) = update_response.update_credential {
            self.credential_repository
                .update_credential(credential_id, update_credential)
                .await?;
        }
        Ok(update_response.result)
    }

    pub async fn initiate_issuance(
        &self,
        request: InitiateIssuanceRequestDTO,
    ) -> Result<InitiateIssuanceResponseDTO, ServiceError> {
        throw_if_org_not_matching_session(&request.organisation_id, &*self.session_provider)?;
        validate_initiate_issuance_request(&request, &self.config)?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await?
        else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let authorization_server = request
            .authorization_server
            .as_ref()
            // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3-2.2
            // ... If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server
            .unwrap_or(&request.issuer);

        let authorization_server = Url::parse(authorization_server)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let interaction_id = Uuid::new_v4();
        let mut authorization_request = OAuthAuthorizationRequest::new(
            request.client_id.clone(),
            request.scope.as_ref().map(|s| s.join(" ")),
            Some(interaction_id.to_string()),
            request.redirect_uri.clone(),
            request
                .authorization_details
                .as_ref()
                .map(|ad| serde_json::json!(ad).to_string()),
        );
        if let Some(issuer_state) = &request.issuer_state {
            authorization_request =
                authorization_request.with_issuer_state(issuer_state.to_owned());
        }

        let authorization_response = self
            .client
            .oauth_client()
            .initiate_authorization_code_flow(authorization_server, authorization_request)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(format!("OAuth request failed: {e:?}")))?;

        let interaction_data = OpenIDAuthorizationCodeFlowInteractionData {
            request,
            code_verifier: authorization_response.code_verifier,
        };
        // store request parameters inside interaction
        let data = serialize_interaction_data(&interaction_data)?;

        let now = OffsetDateTime::now_utc();
        self.interaction_repository
            .create_interaction(Interaction {
                id: interaction_id,
                created_date: now,
                last_modified: now,
                data: Some(data),
                organisation: Some(organisation),
                nonce_id: None,
                interaction_type: InteractionType::Issuance,
            })
            .await?;

        Ok(InitiateIssuanceResponseDTO {
            interaction_id,
            url: authorization_response.url.to_string(),
        })
    }

    pub async fn continue_issuance(
        &self,
        url: impl AsRef<str>,
    ) -> Result<ContinueIssuanceResponseDTO, ServiceError> {
        let url = Url::parse(url.as_ref()).map_err(|error| {
            IssuanceProtocolError::InvalidRequest(format!(
                "Continuation URL has invalid format: {error}"
            ))
        })?;

        let (_, state) = url.query_pairs().find(|(key, _)| key == STATE).ok_or(
            IssuanceProtocolError::InvalidRequest(
                "Continuation URL state parameter not specified".to_string(),
            ),
        )?;

        let (_, authorization_code) = url
            .query_pairs()
            .find(|(key, _)| key == AUTHORIZATION_CODE)
            .ok_or(IssuanceProtocolError::InvalidRequest(
                "Continuation URL authorization_code parameter not specified".to_string(),
            ))?;

        let interaction_id = state.as_ref().try_into().map_err(|_| {
            IssuanceProtocolError::InvalidRequest(
                "Continuation URL state parameter has invalid format".to_string(),
            )
        })?;

        let interaction = self
            .interaction_repository
            .get_interaction(
                &interaction_id,
                &InteractionRelations {
                    organisation: Some(Default::default()),
                },
                None,
            )
            .await?
            .ok_or(EntityNotFoundError::Interaction(interaction_id))?;

        throw_if_org_relation_not_matching_session(
            interaction.organisation.as_ref(),
            &*self.session_provider,
        )?;
        let issuance: OpenIDAuthorizationCodeFlowInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let organisation = interaction
            .organisation
            .ok_or(IssuanceProtocolError::Failed(
                "Organisation must be specified for credential issuance".to_string(),
            ))?;

        if let (None, None) = (
            issuance.request.scope.as_ref(),
            issuance.request.authorization_details.as_ref(),
        ) {
            return Err(IssuanceProtocolError::Failed("Either `scope` or `authorization_details` has to be specified for credential issuance".to_string()).into());
        }

        let issuance_protocol::model::ContinueIssuanceResponseDTO {
            interaction_id,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
        } = self
            .issuance_protocol_provider
            .get_protocol(&issuance.request.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                issuance.request.protocol.clone(),
            ))?
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
                &self.storage_proxy(),
            )
            .await?;

        Ok(ContinueIssuanceResponseDTO {
            interaction_id,
            interaction_type: InteractionType::Issuance,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
        })
    }
}
