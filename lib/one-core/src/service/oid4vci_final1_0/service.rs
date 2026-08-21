use std::collections::HashSet;
use std::str::FromStr;

use futures::FutureExt;
use futures::future::BoxFuture;
use itertools::Itertools;
use one_crypto::utilities::{self, generate_alphanumeric};
use one_dto_mapper::convert_inner;
use secrecy::SecretString;
use shared_types::{
    CredentialId, CredentialSchemaFormatId, CredentialSchemaId, IdentifierId, InteractionId,
    NonceId,
};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use standardized_types::oauth2::token::{ExpiresIn, TokenRequest, TokenResponse};
use standardized_types::openid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, CredentialResponseEntry, NonceResponse,
    NotificationEvent, NotificationRequest, Proofs,
};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use super::dto::{
    OID4VCIFinal1_0IssuerMetadataResponseEnum as IssuerMetadataResponseEnum,
    OID4VCIFinal1_0IssuerMetadataResponseTypeEnum as IssuerMetadataResponseTypeEnum,
    OpenID4VCICredentialResponseDTO,
};
use super::error::OID4VCIFinal1_0ServiceError;
use super::mapper::interaction_data_to_dto;
use super::nonce::{generate_nonce, validate_nonce};
use super::validator::{
    self, extract_wallet_metadata, throw_if_access_token_invalid,
    validate_credential_request_format, validate_pop_audience, validate_timestamps,
    verify_pop_signature, verify_wia_signature, verify_wua_wia_issuers_match, wia_key_source,
};
use crate::clock::now_utc;
use crate::config::ConfigValidationError;
use crate::config::core_config::{BlobStorageType, FormatType, IssuanceProtocolType};
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::exchange::{
    get_issuance_param_pre_authorization_expires_in, get_issuance_param_refresh_token_expires_in,
    get_issuance_param_token_expires_in,
};
use crate::model::blob::{Blob, BlobType};
use crate::model::common::LockType;
use crate::model::credential::{
    Credential, CredentialStateEnum, CredentialType, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::KeyRole;
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::relation::Related;
use crate::proto::credential_validity_manager::is_batch_parent_expired;
use crate::proto::identifier_creator::{IdentifierName, IdentifierRole, RemoteIdentifierRelation};
use crate::proto::jwt::Jwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::transaction_manager::IsolationLevel;
use crate::proto::wallet_instance::WalletUnitStatusCheckResponse;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::issuance_protocol::IssuanceProtocol;
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCIFinal1Params, OpenID4VCIIssuerInteractionDataDTO,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::proof_formatter::{
    OpenID4VCIProofHolderBinding, OpenID4VCIProofJWTFormatter, OpenID4VCIVerifiedProof,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::service::{
    create_credential_offer, oidc_issuer_create_token, parse_access_token, parse_refresh_token,
};
use crate::provider::revocation::model::{Operation, RevocationState};
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{WalletInstanceAttestationDTO, WalletUnitAttestationDTO};
use crate::service::managed_instance::dto::{
    WalletInstanceAttestationClaims, WalletUnitAttestationClaims,
};
use crate::service::ssi_validator::validate_issuance_protocol_type;
use crate::validator::throw_if_credential_state_not_eq;

impl OID4VCIFinal1_0Service {
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
        response_type: IssuerMetadataResponseTypeEnum,
    ) -> Result<IssuerMetadataResponseEnum, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(self.protocol_type, &self.config, protocol_id)
            .error_while("validating protocol type")?;

        let issuance_protocol = self.protocol_provider.get_protocol(protocol_id)?;

        let issuer_identifier = self.get_issuer_identifier(identifier_id).await?;

        match response_type {
            IssuerMetadataResponseTypeEnum::Model => issuance_protocol
                .issuer_metadata(protocol_id, credential_schema_id, &issuer_identifier)
                .await
                .map(Box::new)
                .map(IssuerMetadataResponseEnum::Model)
                .error_while("getting issuer metadata")
                .map_err(Into::into),
            IssuerMetadataResponseTypeEnum::Jwt => self
                .issuer_metadata_cache
                .get_issuer_metadata_jwt(
                    protocol_id,
                    credential_schema_id,
                    issuer_identifier,
                    issuance_protocol,
                )
                .await
                .map(IssuerMetadataResponseEnum::Jwt),
        }
    }

    pub(crate) async fn get_issuer_identifier(
        &self,
        identifier_id: &IdentifierId,
    ) -> Result<Identifier, OID4VCIFinal1_0ServiceError> {
        Ok(self
            .identifier_repository
            .get(*identifier_id)
            .await
            .error_while("getting issuer identifier")?)
    }

    pub async fn oauth_authorization_server(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<AuthorizationServerMetadata, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(self.protocol_type, &self.config, protocol_id)
            .error_while("validating protocol type")?;

        let protocol_base_url =
            self.protocol_base_url
                .as_ref()
                .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                    "Missing base_url".to_owned(),
                ))?;

        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let token_endpoint_auth_methods_supported =
            if credential_schema.requires_wallet_instance_attestation {
                vec![TokenEndpointAuthMethod::AttestJwtClientAuth]
            } else {
                vec![TokenEndpointAuthMethod::None]
            };

        // Per https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-10.1
        // If token_endpoint_auth_methods_supported includes attest_jwt_client_auth, we MUST include these fields
        let (
            client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported,
        ) = if token_endpoint_auth_methods_supported
            .contains(&TokenEndpointAuthMethod::AttestJwtClientAuth)
        {
            (
                Some(vec!["ES256".to_string()]),
                Some(vec!["ES256".to_string()]),
            )
        } else {
            (None, None)
        };

        let credential_issuer =
            format!("{protocol_base_url}/{protocol_id}/{identifier_id}/{credential_schema_id}");
        Ok(AuthorizationServerMetadata {
            issuer: credential_issuer.parse().map_err(|e| {
                OID4VCIFinal1_0ServiceError::MappingError(format!("Invalid issuer URL: {e}"))
            })?,
            authorization_endpoint: Some(
                // ONE-8318: required in iOS EUDI wallet
                format!("{protocol_base_url}/{credential_schema_id}/authorize")
                    .parse()
                    .map_err(|e| {
                        OID4VCIFinal1_0ServiceError::MappingError(format!(
                            "Invalid authorization endpoint URL: {e}"
                        ))
                    })?,
            ),
            token_endpoint: Some(
                format!("{protocol_base_url}/{credential_schema_id}/token")
                    .parse()
                    .map_err(|e| {
                        OID4VCIFinal1_0ServiceError::MappingError(format!(
                            "Invalid token endpoint URL: {e}"
                        ))
                    })?,
            ),
            jwks_uri: None,
            pushed_authorization_request_endpoint: None,
            code_challenge_methods_supported: vec![],
            scopes_supported: vec!["openid".to_string()],
            response_types_supported: vec!["code".to_string(), "token".to_string()],
            grant_types_supported: vec![
                "urn:ietf:params:oauth:grant-type:pre-authorized_code".to_string(),
                "refresh_token".to_string(),
            ],
            token_endpoint_auth_methods_supported,
            challenge_endpoint: None,
            client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported,
            dpop_signing_alg_values_supported: Some(vec!["ES256".to_string()]), // necessary for the EUDI wallet to work
        })
    }

    pub async fn get_credential_offer(
        &self,
        credential_schema_id: CredentialSchemaId,
        credential_id: CredentialId,
    ) -> Result<CredentialOffer, OID4VCIFinal1_0ServiceError> {
        let credential = self
            .credential_repository
            .get_credential(&credential_id)
            .await
            .error_while("getting credential")?;

        if credential.r#type == CredentialType::BatchItem {
            return Err(OID4VCIFinal1_0ServiceError::UnsupportedCredentialType {
                id: credential.id,
                r#type: credential.r#type,
            });
        }

        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.protocol)
            .error_while("validating protocol type")?;

        throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Pending)
            .map_err(|_| OpenID4VCIError::InvalidRequest)?;

        let issuance_protocol_type = self
            .config
            .issuance_protocol
            .get_fields(&credential.protocol)
            .error_while("getting protocol config")?
            .r#type;

        if issuance_protocol_type != self.protocol_type {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }
        let credential_schema = credential.schema.as_ref().await?;

        if credential_schema.id != credential_schema_id {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let interaction =
            credential
                .interaction
                .as_ref()
                .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                    "interaction missing".to_string(),
                ))?;

        let protocol_base_url =
            self.protocol_base_url
                .as_ref()
                .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                    "Missing base_url".to_owned(),
                ))?;

        let identifier_id = credential
            .issuer_identifier
            .as_ref()
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "Missing issuer_identifier".to_owned(),
            ))?
            .id();

        Ok(create_credential_offer(
            protocol_base_url,
            &credential.protocol,
            &interaction.id().to_string(),
            &credential_schema,
            identifier_id,
        )
        .await?)
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        request: CredentialRequest,
    ) -> Result<OpenID4VCICredentialResponseDTO, OID4VCIFinal1_0ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let format = validate_credential_request_format(&schema, &request).await?;

        let interaction_id = parse_access_token(access_token)?;
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    OID4VCIFinal1_0ServiceError::MissingInteractionForAccessToken { interaction_id }
                }
                error => error.error_while("getting interaction").into(),
            })?;

        let interaction_data = interaction_data_to_dto(&interaction)?;
        throw_if_access_token_invalid(&interaction_data, access_token)?;

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting credentials")?;

        let Some(credential) = credentials.iter().find(|credential| {
            credential.r#type != CredentialType::BatchItem
                && credential.schema.id() == *credential_schema_id
        }) else {
            return Err(
                OID4VCIFinal1_0ServiceError::MissingCredentialsForInteraction { interaction_id },
            );
        };

        self.validate_credential_state(credential, &interaction)
            .await?;
        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.protocol)
            .error_while("validating protocol type")?;

        let Some(Proofs::Jwt(jwts)) = request.proofs.as_ref() else {
            return Err(OpenID4VCIError::InvalidOrMissingProof.into());
        };
        let num_proofs = jwts.len() as i32;

        match schema.batch_size {
            Some(batch_size) if num_proofs > batch_size || num_proofs < 1 => {
                tracing::info!(
                    "Batch issuance limit: {batch_size}, #proofs submitted: {num_proofs}"
                );
                return Err(OpenID4VCIError::InvalidRequest.into());
            }
            None if num_proofs != 1 => {
                tracing::info!("Batch issuance not supported, #proofs submitted: {num_proofs}");
                return Err(OpenID4VCIError::InvalidRequest.into());
            }
            _ => {
                tracing::debug!("#proofs submitted: {num_proofs}");
            }
        };

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(&credential.protocol)
            .error_while("getting protocol params")?;

        let mut holder_identifiers = vec![];
        let mut used_nonce_ids = HashSet::new();
        for jwt in jwts {
            let (holder_identifier, nonce_id) = self
                .prepare_holder_identifier_for_proof(
                    jwt,
                    &schema,
                    &params,
                    credential,
                    &interaction,
                )
                .await?;

            used_nonce_ids.insert(nonce_id);
            holder_identifiers.push(holder_identifier);
        }

        // TODO: Properly keep track of _all_ the used nonces
        // For now we allow the nonce to be rotated on credential refresh
        let previous_nonce_id = if credential.state == CredentialStateEnum::Accepted
            && interaction
                .nonce_id
                .is_some_and(|prev| !used_nonce_ids.contains(&prev))
        {
            interaction.nonce_id
        } else {
            None
        };

        // TODO: correctly handle proofs with multiple nonces, for now only store one
        if used_nonce_ids.len() > 1 {
            tracing::warn!("Multiple nonces used within one credential request");
        }
        let nonce_id = used_nonce_ids
            .into_iter()
            .next()
            .ok_or(OpenID4VCIError::InvalidRequest)?;

        self.interaction_repository
            .mark_nonce_as_used(&interaction.id, nonce_id, previous_nonce_id)
            .await
            .map_err(|e| match e {
                DataLayerError::RecordNotUpdated | DataLayerError::AlreadyExists => {
                    OID4VCIFinal1_0ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidNonce)
                }
                e => e.error_while("marking nonce as used").into(),
            })?;

        let result = self
            .transaction_manager
            .tx_with_config(
                self.issue_tx(interaction_id, holder_identifiers, credential, format)
                    .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("issuing credential")?;

        match result {
            Ok(result) => {
                tracing::info!("Issued credential {}", credential.id);
                Ok(result)
            }
            Err(error) => {
                if credential.state == CredentialStateEnum::Offered {
                    // initial issuance failed, mark as Error
                    self.credential_repository
                        .update_credential(
                            credential.id,
                            UpdateCredentialRequest {
                                state: Some(CredentialStateEnum::Error),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating credential")?;
                }

                Err(error.error_while("issuing credential").into())
            }
        }
    }

    async fn prepare_holder_identifier_for_proof(
        &self,
        proof: &str,
        schema: &CredentialSchema,
        params: &OpenID4VCIFinal1Params,
        credential: &Credential,
        interaction: &Interaction,
    ) -> Result<(PreparedIdentifier, NonceId), OID4VCIFinal1_0ServiceError> {
        let token_verifier = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::Authentication,
            certificate_validator: self.certificate_validator.clone(),
        };

        let OpenID4VCIVerifiedProof {
            holder_binding,
            nonce,
            key_attestation,
        } = OpenID4VCIProofJWTFormatter::verify_proof(proof, &token_verifier)
            .await
            .map_err(|err| {
                tracing::debug!("holder proof validation failed: {err}");
                OpenID4VCIError::InvalidOrMissingProof
            })?;

        let nonce = nonce.ok_or(OpenID4VCIError::InvalidNonce)?;
        let Some(nonce_params) = &params.nonce else {
            return Err(
                ConfigValidationError::EntryNotFound("nonce_params".to_string())
                    .error_while("getting nonce params")
                    .into(),
            );
        };
        let nonce_id =
            validate_nonce(nonce_params, self.base_url.to_owned(), &nonce).map_err(|e| {
                tracing::debug!("Nonce validation failed: {e}");
                OpenID4VCIError::InvalidNonce
            })?;

        // Key attestation is expected if wallet storage type is set
        if let Some(key_storage_security) = schema.key_storage_security {
            let Some(key_attestation_jwt) = &key_attestation else {
                tracing::debug!("expected key attestation but none provided");
                return Err(OpenID4VCIError::InvalidOrMissingProof.into());
            };

            let attested_keys = validator::validate_key_attestation(
                key_attestation_jwt,
                &token_verifier,
                key_storage_security.into(),
                params.key_attestation_leeway_seconds,
            )
            .await?;

            let wallet_unit_attestation_status = self
                .holder_wallet_unit_proto
                .check_attestation_status(key_attestation_jwt)
                .await
                .error_while("checking wallet unit attestation status")?;

            if wallet_unit_attestation_status == WalletUnitStatusCheckResponse::Revoked {
                tracing::error!("wallet unit attestation is revoked");
                return Err(OpenID4VCIError::InvalidOrMissingProof.into());
            }

            if schema.requires_wallet_instance_attestation {
                let Some(wallet_instance_attestation_blob_id) =
                    credential.wallet_instance_attestation_blob_id.as_ref()
                else {
                    tracing::debug!(
                        "app attestation required but no wallet app attestation blob ID found"
                    );
                    return Err(OpenID4VCIError::InvalidOrMissingProof.into());
                };

                let db_blob_storage = self
                    .blob_storage_provider
                    .get_blob_storage(BlobStorageType::Db)?;

                let wallet_instance_attestation_blob = db_blob_storage
                    .get(wallet_instance_attestation_blob_id)
                    .await
                    .error_while("getting WIA blob")?
                    .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                        "wallet app attestation blob is None".to_string(),
                    ))?;

                let wia_dto: WalletInstanceAttestationDTO = serde_json::from_slice(
                    &wallet_instance_attestation_blob.value,
                )
                .map_err(|e| {
                    OID4VCIFinal1_0ServiceError::MappingError(format!(
                        "Failed to deserialize WIA blob: {e}"
                    ))
                })?;

                let wia =
                    Jwt::<WalletInstanceAttestationClaims>::decompose_token(&wia_dto.attestation)
                        .error_while("parsing WIA token")?;

                verify_wua_wia_issuers_match(key_attestation_jwt, &wia)?;
            }

            let wua = Jwt::<WalletUnitAttestationClaims>::decompose_token(key_attestation_jwt)
                .error_while("parsing WUA token")?;
            let key_source = wua
                .public_key_source(None)
                .error_while("extracting WUA public key")?;

            if let Some(ecosystem_id) = &interaction.ecosystem {
                let ecosystem = self.ecosystem_provider.get(ecosystem_id)?;
                ecosystem
                    .validate_interaction(
                        &ProtocolArtifact::IssuerIssuance {
                            wallet_provider: key_source,
                        },
                        interaction,
                    )
                    .await
                    .error_while("validating ecosystem")?;
            }

            let proof_signing_key = match &holder_binding {
                OpenID4VCIProofHolderBinding::Did { did, key_id } => {
                    let did_document =
                        self.did_method_provider.resolve(did).await.map_err(|e| {
                            tracing::debug!("failed to resolve DID for key attestation check: {e}");
                            OpenID4VCIError::InvalidOrMissingProof
                        })?;

                    did_document
                        .find_verification_method(Some(key_id), Some(KeyRole::Authentication))
                        .map(|vm| vm.public_key_jwk.clone())
                        .ok_or_else(|| {
                            tracing::debug!(
                                "missing verification method for key attestation check: {key_id}"
                            );
                            OpenID4VCIError::InvalidOrMissingProof
                        })?
                }
                OpenID4VCIProofHolderBinding::Jwk(jwk) => jwk.clone(),
            };

            if !attested_keys.contains(&proof_signing_key) {
                tracing::debug!("proof signing key is not in the attested_keys list");
                return Err(OpenID4VCIError::InvalidOrMissingProof.into());
            }
        } else if key_attestation.is_some() {
            // Key attestation provided but not required
            tracing::debug!("key attestation provided but not required");
            return Err(OpenID4VCIError::InvalidOrMissingProof.into());
        }

        let organisation = schema.organisation.as_ref().await?.to_owned();

        let (identifier, key_id) = match holder_binding {
            OpenID4VCIProofHolderBinding::Did { did, key_id } => {
                let (identifier, _) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        &organisation,
                        &IdentifierDetails::Did(did),
                        IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
                    )
                    .await
                    .error_while("creating remote holder identifier")?;
                (identifier, key_id)
            }
            OpenID4VCIProofHolderBinding::Jwk(jwk) => {
                let (identifier, RemoteIdentifierRelation::Key(key)) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        &organisation,
                        &IdentifierDetails::Key(jwk),
                        IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
                    )
                    .await
                    .error_while("creating remote holder identifier")?
                else {
                    return Err(OID4VCIFinal1_0ServiceError::MappingError(
                        "Invalid identifier type".to_string(),
                    ));
                };

                (identifier, key.id.to_string())
            }
        };

        Ok((
            PreparedIdentifier {
                identifier,
                key_id,
                key_attestation,
            },
            nonce_id.into(),
        ))
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
    async fn issue_tx(
        &self,
        interaction_id: InteractionId,
        mut holder_identifiers: Vec<PreparedIdentifier>,
        credential: &Credential,
        format: CredentialSchemaFormat,
    ) -> Result<OpenID4VCICredentialResponseDTO, OID4VCIFinal1_0ServiceError> {
        // Lock interaction, so that the issuance process is done only by one thread
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, Some(LockType::Update))
            .await
            .error_while("getting interaction")?;
        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        let issuance_protocol = self.protocol_provider.get_protocol(&credential.protocol)?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format.format)?;
        let format_default_expiration = formatter.get_default_expiration();

        let now = crate::clock::now_utc();
        let expires_at = credential.expires_at;
        let default_batch_item_expires_at = now + format_default_expiration;
        let batch_item_expires_at = expires_at
            .map(|e| e.min(default_batch_item_expires_at))
            .unwrap_or(default_batch_item_expires_at);

        let credentials = match credential.r#type {
            CredentialType::Single => {
                let holder_identifier = holder_identifiers
                    .pop()
                    .ok_or(OpenID4VCIError::InvalidOrMissingProof)?;

                // directly issue and modify this credential
                vec![
                    self.issue_single_credential(
                        holder_identifier,
                        credential.id,
                        format.id,
                        issuance_protocol.as_ref(),
                        now,
                    )
                    .await?,
                ]
            }
            CredentialType::BatchParent => {
                let batch_item_template = self
                    .prepare_batch_item(credential.id, batch_item_expires_at)
                    .await?;
                let mut credentials = vec![];
                for holder_identifier in holder_identifiers {
                    let batch_item_id = self
                        .credential_repository
                        .create_credential(Credential {
                            id: Uuid::new_v4().into(),
                            ..batch_item_template.clone()
                        })
                        .await
                        .error_while("creating batch item copy")?;

                    credentials.push(
                        self.issue_single_credential(
                            holder_identifier,
                            batch_item_id,
                            format.id,
                            issuance_protocol.as_ref(),
                            now,
                        )
                        .await?,
                    );
                }

                if credential.state == CredentialStateEnum::Offered {
                    self.credential_repository
                        .update_credential(
                            credential.id,
                            UpdateCredentialRequest {
                                state: Some(CredentialStateEnum::Accepted),
                                issuance_date: Some(now),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating parent credential")?;
                }

                credentials
            }
            CredentialType::BatchItem => {
                return Err(OID4VCIFinal1_0ServiceError::MappingError(
                    "Invalid credential type".to_string(),
                ));
            }
        };

        let notification_id = match &interaction_data.notification_id {
            Some(notification_id) => notification_id.to_owned(),
            None => {
                let notification_id = generate_alphanumeric(32);
                interaction_data.notification_id = Some(notification_id.to_owned());
                let data = serde_json::to_vec(&interaction_data)
                    .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;

                self.interaction_repository
                    .update_interaction(
                        interaction.id,
                        UpdateInteractionRequest {
                            data: Some(Some(data)),
                            ..Default::default()
                        },
                    )
                    .await
                    .error_while("updating interaction")?;

                notification_id
            }
        };

        Ok(OpenID4VCICredentialResponseDTO {
            redirect_uri: credential.redirect_uri.to_owned(),
            standard: CredentialResponse {
                credentials: Some(credentials),
                transaction_id: None,
                interval: None,
                notification_id: Some(notification_id),
            },
        })
    }

    async fn issue_single_credential(
        &self,
        holder_identifier: PreparedIdentifier,
        credential_id: CredentialId,
        format_id: CredentialSchemaFormatId,
        issuance_protocol: &dyn IssuanceProtocol,
        issuance_date: OffsetDateTime,
    ) -> Result<CredentialResponseEntry, OID4VCIFinal1_0ServiceError> {
        let wua_blob_id = if let Some(attestation) = holder_identifier.key_attestation {
            let blob_storage = self
                .blob_storage_provider
                .get_blob_storage(BlobStorageType::Db)?;

            let wua_dto = serde_json::to_vec(&WalletUnitAttestationDTO { attestation })
                .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;
            let wua_blob = Blob::new(wua_dto, BlobType::WalletUnitAttestation);
            blob_storage
                .create(wua_blob.clone())
                .await
                .error_while("creating WUA blob")?;
            Some(wua_blob.id)
        } else {
            None
        };

        let holder_identifier_id = holder_identifier.identifier.id;
        let issued_credential = issuance_protocol
            .issuer_issue_credential(
                &credential_id,
                format_id,
                holder_identifier.identifier,
                holder_identifier.key_id,
            )
            .await
            .error_while("issuing credential")?;

        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    issuance_date: Some(issuance_date),
                    holder_identifier_id: Some(holder_identifier_id),
                    wallet_unit_attestation_blob_id: wua_blob_id,
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        Ok(CredentialResponseEntry {
            credential: issued_credential.into(),
        })
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: CredentialSchemaId,
        access_token: &str,
        request: NotificationRequest,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        let interaction_id = parse_access_token(access_token)?;
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .map_err(|error| match error {
                DataLayerError::EntityNotFound { .. } => {
                    OID4VCIFinal1_0ServiceError::from(OpenID4VCIError::InvalidNotificationRequest)
                }
                error => error.error_while("getting interaction").into(),
            })?;

        let interaction_data = interaction_data_to_dto(&interaction)?;
        throw_if_access_token_invalid(&interaction_data, access_token)?;

        if Some(&request.notification_id) != interaction_data.notification_id.as_ref() {
            return Err(OpenID4VCIError::InvalidNotificationId.into());
        }

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting credentials")?;

        let credentials: Vec<_> = credentials
            .into_iter()
            .filter(|credential| credential.schema.id() == credential_schema_id)
            .collect();
        if credentials.is_empty() {
            return Err(OpenID4VCIError::InvalidNotificationRequest.into());
        }

        let success_log = format!(
            "Processed notification event `{}`, description: `{:?}`, for credentials: [{}]",
            request.event,
            request.event_description,
            credentials.iter().map(|c| c.id).join(", ")
        );

        for credential in credentials {
            self.process_notification_for_credential(credential, &request)
                .await?;
        }

        tracing::info!(message = success_log);
        Ok(())
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: TokenRequest,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
    ) -> Result<TokenResponse, OID4VCIFinal1_0ServiceError> {
        let params = validator::get_config_entity(&self.config).error_while("checking config")?;

        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let interaction_id = match &request {
            TokenRequest::PreAuthorizedCode {
                pre_authorized_code,
                tx_code: _,
            } => Uuid::from_str(pre_authorized_code)
                .map_err(|_| OpenID4VCIError::InvalidRequest)?
                .into(),
            TokenRequest::AuthorizationCode { .. } => {
                return Err(OpenID4VCIError::InvalidGrant.into());
            }
            TokenRequest::RefreshToken { refresh_token } => parse_refresh_token(refresh_token)?,
        };

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction_id)
            .await
            .error_while("getting credentials")?;

        // only batch_parent can be in state `Expiring`,
        // if it's the case, then any other credential related to specified interaction cannot be issued, or token cannot be refreshed
        if credentials
            .iter()
            .any(|c| c.state == CredentialStateEnum::Expiring)
        {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                CredentialStateEnum::Expiring,
            ));
        }

        let credential = credentials.first().ok_or(
            OID4VCIFinal1_0ServiceError::MissingCredentialsForInteraction { interaction_id },
        )?;

        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.protocol)
            .error_while("validating protocol type")?;

        let issuer_identifier_id = if self.protocol_type == IssuanceProtocolType::OpenId4VciFinal1_0
        {
            Some(
                credential
                    .issuer_identifier
                    .as_ref()
                    .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                        "missing issuer_identifier".to_string(),
                    ))?
                    .id(),
            )
        } else {
            None
        };
        let wallet_instance_attestation_token = self
            .validate_oauth_client_attestation(
                oauth_client_attestation,
                oauth_client_attestation_pop,
                &credential_schema,
                credential,
                interaction_id,
                issuer_identifier_id,
                params.oauth_attestation_leeway_seconds,
            )
            .await?;

        // both refresh and access token have the same structure
        let generate_new_token = || {
            SecretString::from(format!(
                "{}.{}",
                interaction_id,
                utilities::generate_alphanumeric(32)
            ))
        };

        let pre_authorization_expires_in =
            get_issuance_param_pre_authorization_expires_in(&self.config, &credential.protocol)
                .error_while("getting issuance params")?;
        let access_token_expires_in =
            get_issuance_param_token_expires_in(&self.config, &credential.protocol)
                .error_while("getting issuance params")?;
        let refresh_token_expires_in =
            get_issuance_param_refresh_token_expires_in(&self.config, &credential.protocol)
                .error_while("getting issuance params")?;

        let tx: BoxFuture<Result<_, OID4VCIFinal1_0ServiceError>> = async {
            // Lock the interaction to ensure exclusive access
            let mut interaction = self
                .interaction_repository
                .get_interaction(&interaction_id, Some(LockType::Update))
                .await
                .error_while("getting interaction")?;
            let interaction_data = interaction_data_to_dto(&interaction)?;

            let mut response = oidc_issuer_create_token(
                &interaction_data,
                &convert_inner(credentials.to_owned()),
                &interaction,
                &request,
                pre_authorization_expires_in,
                access_token_expires_in,
                refresh_token_expires_in,
            )?;

            let now = crate::clock::now_utc();

            for credential in &credentials {
                // If a wallet instance attestation token is provided, we create a new blob and update the credential
                let wallet_instance_attestation_blob_id =
                    match wallet_instance_attestation_token.clone() {
                        Some(wallet_instance_attestation_token) => {
                            let blob_storage = self
                                .blob_storage_provider
                                .get_blob_storage(BlobStorageType::Db)?;

                            let attestation_token =
                                serde_json::to_vec(&wallet_instance_attestation_token).map_err(
                                    |e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()),
                                )?;

                            let blob =
                                Blob::new(attestation_token, BlobType::WalletInstanceAttestation);

                            blob_storage
                                .create(blob.clone())
                                .await
                                .error_while("creating WIA blob")?;
                            Some(blob.id)
                        }
                        None => None,
                    };

                let mut state_update = UpdateCredentialRequest {
                    wallet_instance_attestation_blob_id,
                    ..Default::default()
                };

                if let TokenRequest::PreAuthorizedCode { .. } = &request {
                    state_update.state = Some(CredentialStateEnum::Offered);
                }

                // Only update the credential if there is a change
                if state_update.wallet_instance_attestation_blob_id.is_some()
                    || state_update.state.is_some()
                {
                    self.credential_repository
                        .update_credential(credential.id, state_update)
                        .await
                        .error_while("updating credential")?;
                }
            }

            let schema_format = credential_schema.format().await?;
            let credential_format_type = self
                .config
                .format
                .get_fields(&schema_format)
                .error_while("getting format config")?
                .r#type;

            // we add refresh token for mdoc and batches
            if credential_format_type == FormatType::Mdoc || credential_schema.batch_size.is_some()
            {
                response.refresh_token = Some(generate_new_token());
                response.refresh_token_expires_in =
                    Some(ExpiresIn((now + refresh_token_expires_in).unix_timestamp()));
            }

            let interaction_data: OpenID4VCIIssuerInteractionDataDTO = (&response).try_into()?;
            let data = serde_json::to_vec(&interaction_data)
                .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;
            interaction.data = Some(data);

            self.interaction_repository
                .update_interaction(interaction.id, interaction.into())
                .await
                .error_while("updating credential interaction")?;
            Ok(response)
        }
        .boxed();
        let result = self
            .transaction_manager
            .tx(tx)
            .await
            .error_while("creating token")?;

        let result = match result {
            Ok(result) => result,
            // Invalid tx-code entry means the issuance failed, we do not allow to retry
            Err(
                err @ OID4VCIFinal1_0ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidGrant),
            ) if matches!(
                request,
                TokenRequest::PreAuthorizedCode {
                    pre_authorized_code: _,
                    tx_code: Some(_)
                }
            ) =>
            {
                for credential in &credentials {
                    self.credential_repository
                        .update_credential(
                            credential.id,
                            UpdateCredentialRequest {
                                state: Some(CredentialStateEnum::Error),
                                ..Default::default()
                            },
                        )
                        .await
                        .error_while("updating credential")?;
                }
                return Err(err);
            }
            Err(err) => {
                return Err(err);
            }
        };

        tracing::info!(
            "Issued access token for issuance of credential {}",
            credential.id
        );
        Ok(result)
    }

    #[expect(clippy::too_many_arguments)]
    async fn validate_oauth_client_attestation(
        &self,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
        credential_schema: &CredentialSchema,
        credential: &Credential,
        interaction_id: InteractionId,
        issuer_identifier_id: Option<IdentifierId>,
        leeway: Duration,
    ) -> Result<Option<WalletInstanceAttestationDTO>, OID4VCIFinal1_0ServiceError> {
        // If the credential schema does not require client attestation, no tokens are expected
        if !credential_schema.requires_wallet_instance_attestation {
            if oauth_client_attestation.is_some() || oauth_client_attestation_pop.is_some() {
                return Err(OpenID4VCIError::InvalidRequest.into());
            }
            return Ok(None);
        }

        // Parse tokens
        let wallet_instance_attestation_token =
            oauth_client_attestation.ok_or(OpenID4VCIError::InvalidRequest)?;
        let proof_of_key_possesion_token =
            oauth_client_attestation_pop.ok_or(OpenID4VCIError::InvalidRequest)?;

        let wallet_instance_attestation = Jwt::<WalletInstanceAttestationClaims>::decompose_token(
            wallet_instance_attestation_token,
        )
        .error_while("parsing WIA token")?;
        let proof_of_key_possession = Jwt::<()>::decompose_token(proof_of_key_possesion_token)
            .error_while("parsing WUA token")?;

        // Validate timestamps for both tokens
        validate_timestamps(&wallet_instance_attestation, leeway)?;
        validate_timestamps(&proof_of_key_possession, leeway)?;

        // Validate proof of possession audience
        let expected_audience = {
            let base_url = self.protocol_base_url.as_ref().ok_or(
                OID4VCIFinal1_0ServiceError::MappingError("missing protocol_base_url".to_string()),
            )?;
            let protocol_id = &credential.protocol;
            let credential_schema_id = credential_schema.id;
            if let Some(issuer_identifier_id) = issuer_identifier_id {
                format!("{base_url}/{protocol_id}/{issuer_identifier_id}/{credential_schema_id}")
            } else {
                format!("{base_url}/{protocol_id}/{credential_schema_id}")
            }
        };
        validate_pop_audience(&proof_of_key_possession, &expected_audience)?;

        // Verify signatures
        verify_pop_signature(
            &proof_of_key_possession,
            &wallet_instance_attestation,
            self.key_algorithm_provider.as_ref(),
        )?;

        let verifier = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        };

        verify_wia_signature(&wallet_instance_attestation, &verifier).await?;

        let key_source = wia_key_source(&wallet_instance_attestation)?;

        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("getting interaction")?;
        if let Some(ecosystem_id) = &interaction.ecosystem {
            let ecosystem = self.ecosystem_provider.get(ecosystem_id)?;
            ecosystem
                .validate_interaction(
                    &ProtocolArtifact::IssuerIssuance {
                        wallet_provider: key_source,
                    },
                    &interaction,
                )
                .await
                .error_while("validating ecosystem")?;
        }

        // Extract wallet metadata
        let (name, link) = extract_wallet_metadata(&wallet_instance_attestation)?;

        Ok(Some(WalletInstanceAttestationDTO {
            name,
            link,
            attestation: wallet_instance_attestation_token.to_owned(),
        }))
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<NonceResponse, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(self.protocol_type, &self.config, protocol_id)
            .error_while("validating protocol type")?;

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(protocol_id)
            .error_while("getting protocol params")?;
        let Some(params) = params.nonce else {
            return Err(ConfigValidationError::TypeNotFound(protocol_id.to_string())
                .error_while("getting nonce params")
                .into());
        };

        let c_nonce = generate_nonce(params, self.base_url.to_owned()).await?;
        Ok(NonceResponse { c_nonce })
    }

    async fn prepare_batch_item(
        &self,
        parent_credential_id: CredentialId,
        expires_at: OffsetDateTime,
    ) -> Result<Credential, OID4VCIFinal1_0ServiceError> {
        let now = crate::clock::now_utc();
        let parent_credential = self
            .credential_repository
            .get_credential(&parent_credential_id)
            .await
            .error_while("loading credential")?;

        Ok(Credential {
            id: Uuid::new_v4().into(),
            created_date: now,
            issuance_date: Some(now),
            r#type: CredentialType::BatchItem,
            parent: Some(Related::new(
                parent_credential_id,
                self.credential_repository.clone(),
            )),
            webhook_url: None,
            interaction: None,
            claims: Default::default(),
            expires_at: Some(expires_at),
            // state and last_modified are reused from the parent credential,
            // so that they can be checked in the issuance protocol (e.g. MSO refresh rate limiting)
            // they will be updated inside the issuance protocol logic
            ..parent_credential
        })
    }

    async fn process_notification_for_credential(
        &self,
        credential: Credential,
        notification: &NotificationRequest,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(self.protocol_type, &self.config, &credential.protocol)
            .error_while("validating protocol type")?;

        match (credential.state, &notification.event) {
            (
                CredentialStateEnum::Accepted
                | CredentialStateEnum::Suspended
                | CredentialStateEnum::Revoked,
                _,
            ) => {
                // ok, can be processed
            }
            // repeated requests also allowed
            (CredentialStateEnum::Error, NotificationEvent::CredentialFailure)
            | (CredentialStateEnum::Rejected, NotificationEvent::CredentialDeleted) => {
                return Ok(());
            }
            // anything else is invalid
            _ => {
                return Err(OpenID4VCIError::InvalidNotificationRequest.into());
            }
        };

        let new_state = match notification.event {
            NotificationEvent::CredentialAccepted => {
                // nothing to do
                return Ok(());
            }
            NotificationEvent::CredentialFailure => CredentialStateEnum::Error,
            NotificationEvent::CredentialDeleted => CredentialStateEnum::Rejected,
        };

        if credential.state == new_state {
            // nothing to do
            return Ok(());
        }

        let schema = credential.schema.as_ref().await?;

        let format = schema.format().await?;
        let formatter = self.formatter_provider.get_credential_formatter(&format)?;
        let revocation_method = match schema.revocation_method_id(formatter.as_ref()) {
            Some(method_id) => Some(
                self.revocation_method_provider
                    .get_revocation_method(method_id)?,
            ),
            None => None,
        };

        self.credential_repository
            .update_credential(
                credential.id,
                UpdateCredentialRequest {
                    state: Some(new_state),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        // mark the credential as revoked (if supported and not done before)
        if matches!(
            credential.state,
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended
        ) && let Some(revocation_method) = revocation_method
            && revocation_method
                .get_capabilities()
                .operations
                .contains(&Operation::Revoke)
        {
            revocation_method
                .mark_credential_as(&credential, RevocationState::Revoked)
                .await
                .error_while("marking credential status")?;
        }

        Ok(())
    }

    async fn validate_credential_state(
        &self,
        credential: &Credential,
        interaction: &Interaction,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        if credential.state.is_terminal() {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.state,
            ));
        }
        if credential.state == CredentialStateEnum::Expiring {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.state,
            ));
        }
        if is_batch_parent_expired(credential, Some(interaction), now_utc())
            .error_while("checking credential state")?
        {
            self.credential_repository
                .update_credential(
                    credential.id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Expired),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating expired credential")?;
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.state,
            ));
        }
        Ok(())
    }
}

struct PreparedIdentifier {
    identifier: Identifier,
    key_id: String,
    key_attestation: Option<String>,
}
