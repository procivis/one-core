use std::borrow::Cow;
use std::sync::Arc;

use indexmap::IndexMap;
use shared_types::{CredentialId, DidId, IdentifierId, KeyId};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::SSIHolderService;
use super::dto::{CredentialConfigurationSupportedResponseDTO, HandleInvitationResultDTO};
use crate::common_mapper::value_to_model_claims;
use crate::common_validator::throw_if_credential_state_not_eq;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::claim::Claim;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidRelations, KeyFilter, KeyRole};
use crate::model::history::HistoryAction;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::interaction::{Interaction, InteractionId, InteractionRelations};
use crate::model::key::Key;
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::provider::blob_storage_provider::BlobStorageType;
use crate::provider::issuance_protocol::dto::Features;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::HandleInvitationOperationsImpl;
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::map_proof_types_supported;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    InvitationResponseDTO, OpenID4VCIProofTypeSupported, SubmitIssuerResponse, UpdateResponse,
};
use crate::provider::issuance_protocol::{IssuanceProtocol, serialize_interaction_data};
use crate::provider::key_storage::model::KeySecurity;
use crate::service::error::{
    BusinessLogicError, EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};
use crate::service::ssi_holder::dto::{
    InitiateIssuanceRequestDTO, InitiateIssuanceResponseDTO, OpenIDAuthorizationServerMetadata,
};
use crate::service::ssi_holder::validator::{
    validate_holder_capabilities, validate_initiate_issuance_request,
};
use crate::service::storage_proxy::StorageProxyImpl;
use crate::util::history::log_history_event_credential;

impl SSIHolderService {
    pub async fn accept_credential(
        &self,
        interaction_id: &InteractionId,
        did_id: Option<DidId>,
        identifier_id: Option<IdentifierId>,
        key_id: Option<KeyId>,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    interaction: Some(InteractionRelations {
                        organisation: Some(OrganisationRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(Default::default()),
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

        let identifier = match (did_id, identifier_id) {
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

        let did = identifier
            .did
            .to_owned()
            .ok_or(ServiceError::BusinessLogic(
                BusinessLogicError::IncompatibleHolderIdentifier,
            ))?;

        let key_filter = KeyFilter::role_filter(KeyRole::Authentication);
        let selected_key = match key_id {
            Some(key_id) => did
                .find_key(&key_id, &key_filter)?
                .ok_or(ValidationError::KeyNotFound)?,
            None => {
                did.find_first_matching_key(&key_filter)?
                    .ok_or(ValidationError::InvalidKey(
                        "No key with role authentication available".to_string(),
                    ))?
            }
        };

        let holder_jwk_key_id = did.verification_method_id(selected_key);
        let selected_key = &selected_key.key;

        let key_security = self
            .key_provider
            .get_key_storage(&selected_key.storage_type)
            .ok_or_else(|| MissingProviderError::KeyStorage(selected_key.storage_type.clone()))?
            .get_capabilities()
            .security;

        // Errors are gathered into vec, so we can try to accept all credentials.
        let mut errors = vec![];

        for credential in credentials {
            if let Err(error) = self
                .accept_and_save_credential(
                    &credential,
                    &did,
                    &identifier,
                    &key_security,
                    selected_key,
                    &holder_jwk_key_id,
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

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_and_save_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        holder_identifer: &Identifier,
        key_security: &[KeySecurity],
        selected_key: &Key,
        holder_jwk_key_id: &str,
        tx_code: Option<String>,
    ) -> Result<(), ServiceError> {
        throw_if_credential_state_not_eq(credential, CredentialStateEnum::Pending)?;

        let wallet_storage_matches = match credential
            .schema
            .as_ref()
            .and_then(|schema| schema.wallet_storage_type.as_ref())
        {
            Some(WalletStorageTypeEnum::Hardware) => key_security.contains(&KeySecurity::Hardware),
            Some(WalletStorageTypeEnum::Software) => key_security.contains(&KeySecurity::Software),
            Some(WalletStorageTypeEnum::RemoteSecureElement) => {
                key_security.contains(&KeySecurity::RemoteSecureElement)
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
            self.certificate_repository.clone(),
            self.certificate_validator.clone(),
            self.key_repository.clone(),
            self.identifier_repository.clone(),
            self.did_method_provider.clone(),
            self.key_algorithm_provider.clone(),
        );

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        let format = &schema.format;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(format)
            .ok_or(ServiceError::MissingProvider(
                MissingProviderError::Formatter(format.to_owned()),
            ))?;

        validate_holder_capabilities(
            &self.config,
            holder_did,
            holder_identifer,
            selected_key,
            &formatter.get_capabilities(),
            self.key_algorithm_provider.as_ref(),
        )?;

        let issuer_response = self
            .issuance_protocol_provider
            .get_protocol(&credential.protocol)
            .ok_or(MissingProviderError::ExchangeProtocol(
                credential.protocol.clone(),
            ))?
            .holder_accept_credential(
                credential,
                holder_did,
                selected_key,
                Some(holder_jwk_key_id.to_string()),
                &storage_access,
                tx_code.clone(),
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
                    holder_identifier_id: Some(holder_identifer.id),
                    key: Some(selected_key.id),
                    claims: Some(claims),
                    credential_blob_id: Some(blob_id),
                    ..Default::default()
                },
            )
            .await?;

        log_history_event_credential(&*self.history_repository, credential, HistoryAction::Issued)
            .await;

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

        let mut result: Result<(), ServiceError> = Ok(());

        for credential in credentials {
            throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Pending).or(
                throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Offered),
            )?;

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

            if let Err(err) = self.reject_single_credential(&credential, &*protocol).await {
                result = Err(err);
            };
        }

        result
    }

    async fn reject_single_credential(
        &self,
        credential: &Credential,
        protocol: &dyn IssuanceProtocol,
    ) -> Result<(), ServiceError> {
        protocol.holder_reject_credential(credential).await?;

        self.credential_repository
            .update_credential(
                credential.id,
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
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
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

        let handle_operations = HandleInvitationOperationsImpl::new(
            organisation.clone(),
            self.credential_schema_repository.clone(),
            self.vct_type_metadata_cache.clone(),
            self.client.clone(),
        );

        let InvitationResponseDTO {
            credentials,
            interaction_id,
            tx_code,
            mut issuer_proof_type_supported,
        } = issuance_protocol
            .holder_handle_invitation(url, organisation, &storage_access, &handle_operations)
            .await?;

        let mut holder_proof_types_supported = self
            .key_algorithm_provider
            .supported_verification_jose_alg_ids();
        holder_proof_types_supported.sort();

        let result = HandleInvitationResultDTO::Credential {
            interaction_id,
            credential_ids: credentials.iter().map(|c| c.id).collect(),
            tx_code,
            credential_configurations_supported: credentials
                .iter()
                .map(|c| {
                    (
                        c.id,
                        CredentialConfigurationSupportedResponseDTO {
                            proof_types_supported: Some(map_proof_types_supported(
                                self.resolve_proof_types_supported(
                                    issuer_proof_type_supported.remove(&c.id).flatten(),
                                    &holder_proof_types_supported,
                                ),
                            )),
                        },
                    )
                })
                .collect(),
        };

        for mut credential in credentials {
            credential.protocol = exchange.to_owned();
            self.credential_repository
                .create_credential(credential)
                .await?;
        }

        Ok(result)
    }

    async fn resolve_update_issuer_response(
        &self,
        update_response: UpdateResponse<SubmitIssuerResponse>,
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

    fn resolve_proof_types_supported(
        &self,
        issuer_proof_type_supported: Option<IndexMap<String, OpenID4VCIProofTypeSupported>>,
        holder_proof_type_supported: &[String],
    ) -> Vec<String> {
        let Some(mut issuer_proof_type_supported) = issuer_proof_type_supported else {
            return holder_proof_type_supported.to_vec();
        };

        let Some(issuer_proof_type_supported) = issuer_proof_type_supported.shift_remove("jwt")
        else {
            return vec![];
        };

        let holder_proof_type_supported = if !holder_proof_type_supported.is_sorted() {
            let mut sorted_holder_proof_type = holder_proof_type_supported.to_vec();
            sorted_holder_proof_type.sort();
            Cow::Owned(sorted_holder_proof_type)
        } else {
            Cow::Borrowed(holder_proof_type_supported)
        };

        issuer_proof_type_supported
            .proof_signing_alg_values_supported
            .into_iter()
            .filter(|t| holder_proof_type_supported.binary_search(t).is_ok())
            .collect()
    }

    pub async fn initiate_issuance(
        &self,
        request: InitiateIssuanceRequestDTO,
    ) -> Result<InitiateIssuanceResponseDTO, ServiceError> {
        validate_initiate_issuance_request(&request, &self.config)?;

        let Some(organisation) = self
            .organisation_repository
            .get_organisation(&request.organisation_id, &Default::default())
            .await?
        else {
            return Err(BusinessLogicError::MissingOrganisation(request.organisation_id).into());
        };

        let issuer = Url::parse(&request.issuer)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        // obtain OAuth 2.0 Authorization server metadata (https://datatracker.ietf.org/doc/html/rfc8414#section-3)
        // prepend `.well-known/oauth-authorization-server` to path to construct provider metadata endpoint
        let original_path_segments: Vec<_> = issuer
            .path_segments()
            .ok_or(IssuanceProtocolError::Failed(
                "invalid issuer URL".to_string(),
            ))?
            .filter_map(|segment| {
                if segment.is_empty() {
                    None
                } else {
                    Some(segment.to_string())
                }
            })
            .collect();

        let mut authorization_server_metadata_endpoint = issuer;
        {
            let mut segments = authorization_server_metadata_endpoint
                .path_segments_mut()
                .map_err(|_| IssuanceProtocolError::Failed("invalid issuer URL".to_string()))?;

            segments
                .clear()
                .push(".well-known")
                .push("oauth-authorization-server");
            if !original_path_segments.is_empty() {
                segments.extend(&original_path_segments);
            }
        }

        let authorization_server_metadata: OpenIDAuthorizationServerMetadata = self
            .client
            .get(authorization_server_metadata_endpoint.as_str())
            .send()
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .error_for_status()
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .json()
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        // store request parameters inside interaction
        let data = serialize_interaction_data(&request)?;

        let now = OffsetDateTime::now_utc();
        let interaction_id = self
            .interaction_repository
            .create_interaction(Interaction {
                id: Uuid::new_v4(),
                created_date: now,
                last_modified: now,
                host: None,
                data: Some(data),
                organisation: Some(organisation),
            })
            .await?;

        // construct authorization URL by adding all necessary query parameters
        let mut authorization_url = authorization_server_metadata.authorization_endpoint;
        {
            let mut query = authorization_url.query_pairs_mut();
            query.append_pair("client_id", &request.client_id);
            query.append_pair("state", &interaction_id.to_string());
            if let Some(redirect_uri) = &request.redirect_uri {
                query.append_pair("redirect_uri", redirect_uri);
            }
            if let Some(scope) = &request.scope {
                query.append_pair("scope", &scope.join(" "));
            }
            if let Some(authorization_details) = &request.authorization_details {
                query.append_pair(
                    "authorization_details",
                    &serde_json::json!(authorization_details).to_string(),
                );
            }
        }

        Ok(InitiateIssuanceResponseDTO {
            url: authorization_url.to_string(),
        })
    }
}
