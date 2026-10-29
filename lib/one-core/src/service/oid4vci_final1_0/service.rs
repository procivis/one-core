use std::collections::HashSet;

use futures::FutureExt;
use futures::future::BoxFuture;
use itertools::Itertools;
use one_crypto::jwe::{Header as JweHeader, extract_jwe_header};
use one_crypto::utilities::generate_alphanumeric;
use one_dto_mapper::convert_inner;
use secrecy::SecretString;
use shared_types::{
    BlobId, CredentialId, CredentialSchemaFormatId, CredentialSchemaId, DpopNonce, IdentifierId,
    InteractionId, NonceId, RevocationListEntryId,
};
use standardized_types::iana::EncryptionKeyManagementAlgorithm;
use standardized_types::oauth2::TokenType;
use standardized_types::oauth2::attestation_based_client_auth::{
    ChallengeResponse, ClientAttestationPopMethod, OAuthClientAttestationPopCustomClaims,
};
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::dynamic_client_registration::TokenEndpointAuthMethod;
use standardized_types::oauth2::token::{ExpiresIn, TokenRequest, TokenResponse};
use standardized_types::openid4vci::{
    CredentialOffer, CredentialRequest, CredentialResponse, CredentialResponseEntry, NonceResponse,
    NotificationEvent, NotificationRequest, Proofs, ResponseEncryption,
};
use time::OffsetDateTime;
use url::Url;
use uuid::Uuid;

use super::OID4VCIFinal1_0Service;
use super::dto::{
    CredentialRequestPayload, CredentialResponsePayload,
    OID4VCIFinal1_0IssuerMetadataResponseEnum as IssuerMetadataResponseEnum,
    OID4VCIFinal1_0MetadataResponseTypeEnum as IssuerMetadataResponseTypeEnum,
    OpenID4VCICredentialResponseDTO, ProtocolSelection,
};
use super::error::{OID4VCIFinal1_0ServiceError, WalletAttestationError};
use super::mapper::{
    allocate_notification_ids, interaction_data_to_dto, interaction_id_from_token_request,
    issued_credential_update, map_dpop_params, notification_id_for_format, offered_formats,
};
use super::validator::{
    self, client_instance_key_thumbprint, extract_wallet_metadata, throw_if_access_token_invalid,
    validate_credential_issuable, validate_credential_request_format, validate_pop_audience,
    validate_pop_issuer, validate_response_encryption, validate_timestamps,
    verify_ka_wia_issuers_match, verify_pop_signature, verify_wia_signature,
};
use crate::clock::now_utc;
use crate::config::ConfigValidationError;
use crate::config::core_config::{BlobStorageType, FormatType, IssuanceProtocolType};
use crate::error::{
    ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError,
};
use crate::mapper::exchange::{
    get_issuance_param_pre_authorization_expires_in, get_issuance_param_refresh_token_expires_in,
    get_issuance_param_token_expires_in,
};
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::common::{LockType, SortDirection};
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialStateEnum, CredentialType, IssuerCredentialData,
    SortableCredentialColumn, UpdateCredentialRequest,
};
use crate::model::credential_schema::CredentialSchema;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::KeyRole;
use crate::model::history::HistoryErrorMetadata;
use crate::model::identifier::Identifier;
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery, ListSorting};
use crate::model::relation::Related;
use crate::model::revocation_list::{
    UpdateRevocationListEntryId, UpdateRevocationListEntryRequest,
};
use crate::proto::credential_validity_manager::is_batch_parent_expired;
use crate::proto::dpop_handler::{
    DpopHandlerError, DpopParams, ExpectedProofValues, ProofValidationOutput,
};
use crate::proto::identifier_creator::{IdentifierName, IdentifierRole, RemoteIdentifierRelation};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::key_verification::KeyVerification;
use crate::provider::ProviderExt;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::ecosystem::model::{ProtocolArtifact, WalletAttestationArtifact};
use crate::provider::issuance_protocol::error::OpenID4VCIError;
use crate::provider::issuance_protocol::model::IssuedCredential;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    FormatNotification, OpenID4VCIFinal1Params, OpenID4VCIIssuerInteractionDataDTO,
    OpenID4VCNonceParams, SWISS_PROFILE_ISSUANCE_VERSION, SwissProfileHeader,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::proof_formatter::{
    OpenID4VCIProofHolderBinding, OpenID4VCIProofJWTFormatter, OpenID4VCIVerifiedProof,
};
use crate::provider::issuance_protocol::openid4vci_final1_0::service::{
    create_credential_offer, oidc_issuer_create_token, parse_access_token,
};
use crate::provider::revocation::model::{Operation, RevocationState};
use crate::repository::error::DataLayerError;
use crate::service::credential::dto::{WalletInstanceAttestationDTO, WalletUnitAttestationDTO};
use crate::service::managed_instance::dto::WalletInstanceAttestationClaims;
use crate::service::ssi_validator::validate_issuance_protocol_type;
use crate::util::jwe::{build_jwe, decrypt_jwe};
use crate::util::key_agreement::key_agreement_keys;
use crate::util::nonce::{NonceContext, generate_nonce, validate_nonce};
use crate::validator::throw_if_credential_state_not_eq;

impl OID4VCIFinal1_0Service {
    pub async fn get_issuer_metadata(
        &self,
        protocol_id: &str,
        identifier_id: &IdentifierId,
        credential_schema_id: &CredentialSchemaId,
        response_type: IssuerMetadataResponseTypeEnum,
    ) -> Result<IssuerMetadataResponseEnum, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )
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
                    self.swiss_profile_header(protocol_id)?,
                )
                .await
                .map(IssuerMetadataResponseEnum::Jwt),
        }
    }

    /// Swiss Profile header claims the signed metadata of `protocol_id` carries, empty unless the
    /// protocol runs in swiyu mode.
    fn swiss_profile_header(
        &self,
        protocol_id: &str,
    ) -> Result<SwissProfileHeader, OID4VCIFinal1_0ServiceError> {
        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(protocol_id)
            .error_while("getting protocol params")?;

        Ok(swiss_profile_header(&params))
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
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )
        .error_while("validating protocol type")?;

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(protocol_id)
            .error_while("getting protocol params")?;

        let issuance_protocol = self.protocol_provider.get_protocol(protocol_id)?;
        let protocol_base_url = issuance_protocol.protocol_base_url().ok_or(
            OID4VCIFinal1_0ServiceError::MappingError("Missing base_url".to_owned()),
        )?;

        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let (token_endpoint_auth_methods_supported, client_attestation_pop_methods_supported) =
            if credential_schema
                .wallet_attestation
                .require_instance_attestation
            {
                let mut auth_methods = vec![TokenEndpointAuthMethod::AttestJwtClientAuth];
                let mut pop_methods = vec![ClientAttestationPopMethod::AttestationPopJwt];
                // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-5.2
                if params.dpop.is_some() {
                    auth_methods.push(TokenEndpointAuthMethod::AttestJwtClientAuthDpop);
                    pop_methods.push(ClientAttestationPopMethod::DpopCombined);
                }
                (auth_methods, Some(pop_methods))
            } else {
                (vec![TokenEndpointAuthMethod::None], None)
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

        let challenge_endpoint = if params.oauth_attestation_challenge.is_some() {
            Some(
                format!("{protocol_base_url}/{protocol_id}/challenge")
                    .parse()
                    .map_err(|e| {
                        OID4VCIFinal1_0ServiceError::MappingError(format!(
                            "Invalid challenge endpoint URL: {e}"
                        ))
                    })?,
            )
        } else {
            None
        };

        let credential_issuer =
            format!("{protocol_base_url}/{protocol_id}/{identifier_id}/{credential_schema_id}");
        let metadata = AuthorizationServerMetadata {
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
            challenge_endpoint,
            client_attestation_signing_alg_values_supported,
            client_attestation_pop_signing_alg_values_supported,
            client_attestation_pop_methods_supported,
            dpop_signing_alg_values_supported: self.dpop_signing_alg_values_supported(&params)?,
            signed_metadata: None,
        };

        let metadata_result = async {
            let issuer_identifier = self.get_issuer_identifier(identifier_id).await?;
            self.issuer_metadata_cache
                .get_authorization_server_metadata_jwt(
                    protocol_id,
                    credential_schema_id,
                    issuer_identifier,
                    metadata.clone(),
                    swiss_profile_header(&params),
                )
                .await
        }
        .await;
        let signed_metadata = match metadata_result {
            Ok(jwt) => Some(jwt),
            Err(OID4VCIFinal1_0ServiceError::MissingAuthenticationCapableKey(identifier_id)) => {
                tracing::debug!(
                    "Omitting signed authorization server metadata: identifier {identifier_id} has no Authentication capable key"
                );
                None
            }
            Err(error) => {
                tracing::warn!("Failed to sign authorization server metadata: {error}");
                None
            }
        };

        Ok(AuthorizationServerMetadata {
            signed_metadata,
            ..metadata
        })
    }

    fn dpop_signing_alg_values_supported(
        &self,
        params: &OpenID4VCIFinal1Params,
    ) -> Result<Option<Vec<String>>, OID4VCIFinal1_0ServiceError> {
        let Some(dpop_params) = &params.dpop else {
            return Ok(None);
        };
        let dpop_signing_algs = dpop_params
            .signing_algorithms
            .iter()
            .map(|alg| {
                let key_algorithm = self.key_algorithm_provider.key_algorithm_from_type(*alg)?;
                key_algorithm.ensure_enabled()?;
                Ok::<_, NestedError>(key_algorithm.issuance_jose_alg_id())
            })
            .collect::<Result<_, _>>()
            .error_while("collecting supported DPoP singing algorithms")?;
        Ok(Some(dpop_signing_algs))
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

        if matches!(
            credential,
            Credential::IssuerBatchItem { .. } | Credential::HolderBatchItem { .. }
        ) {
            return Err(OID4VCIFinal1_0ServiceError::UnsupportedCredentialType {
                id: credential.common().id,
                r#type: CredentialType::BatchItem,
            });
        }

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.common().protocol,
        )
        .error_while("validating protocol type")?;

        throw_if_credential_state_not_eq(&credential, CredentialStateEnum::Pending)
            .map_err(|_| OpenID4VCIError::InvalidRequest)?;

        let credential_schema = credential.common().schema.as_ref().await?;

        if credential_schema.id != credential_schema_id {
            return Err(OpenID4VCIError::InvalidRequest.into());
        }

        let interaction = credential
            .common()
            .interaction
            .as_ref()
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "interaction missing".to_string(),
            ))?
            .as_ref()
            .await?;
        let interaction_data = interaction_data_to_dto(&interaction)?;
        let formats = offered_formats(&credential_schema, &interaction_data).await?;

        let issuance_protocol = self
            .protocol_provider
            .get_protocol(&credential.common().protocol)?;
        let protocol_base_url = issuance_protocol.protocol_base_url().ok_or(
            OID4VCIFinal1_0ServiceError::MappingError("Missing base_url".to_owned()),
        )?;

        let identifier_id = credential.issuer()?.data.identifier.id();

        Ok(create_credential_offer(
            &protocol_base_url,
            &credential.common().protocol,
            &interaction.id.to_string(),
            &credential_schema,
            &formats,
            identifier_id,
        )?)
    }

    pub async fn create_credential(
        &self,
        credential_schema_id: &CredentialSchemaId,
        access_token: &str,
        dpop_proof: Option<&str>,
        request: CredentialRequestPayload,
    ) -> Result<(CredentialResponsePayload, Option<DpopNonce>), OID4VCIFinal1_0ServiceError> {
        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

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
            !matches!(
                credential,
                Credential::IssuerBatchItem { .. } | Credential::HolderBatchItem { .. }
            ) && credential.common().schema.id() == *credential_schema_id
        }) else {
            return Err(
                OID4VCIFinal1_0ServiceError::MissingCredentialsForInteraction { interaction_id },
            );
        };
        let dpop_nonce = self
            .validate_access_token_binding(
                interaction_id,
                interaction_data.dpop_jkt.as_deref(),
                access_token,
                dpop_proof,
                &credential.common().protocol,
                &format!("{credential_schema_id}/credential"),
            )
            .await?;

        self.validate_credential_state(credential, &interaction)
            .await?;
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.common().protocol,
        )
        .error_while("validating protocol type")?;

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(&credential.common().protocol)
            .error_while("getting protocol params")?;

        // decrypting needs the issuer identity, so it can only happen once the access token
        // resolved the credential this request belongs to
        let request = self
            .decrypt_credential_request(request, credential, &params)
            .await?;

        let format = validate_credential_request_format(&schema, &request).await?;
        if !offered_formats(&schema, &interaction_data)
            .await?
            .iter()
            .any(|offered| offered.id == format.id)
        {
            return Err(OpenID4VCIError::UnsupportedCredentialType.into());
        }

        let issuance_protocol = self
            .protocol_provider
            .get_protocol(&credential.common().protocol)?;
        validate_response_encryption(
            request.credential_response_encryption.as_ref(),
            &params,
            &*issuance_protocol,
            &*self.key_algorithm_provider,
        )?;

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

        let used_nonce_ids = used_nonce_ids.into_iter().collect();
        self.interaction_repository
            .mark_nonces_as_used(&interaction.id, used_nonce_ids)
            .await
            .map_err(|e| match e {
                DataLayerError::AlreadyExists(_) => {
                    OID4VCIFinal1_0ServiceError::OpenID4VCIError(OpenID4VCIError::InvalidNonce)
                }
                e => e.error_while("marking nonce as used").into(),
            })?;

        let notification_id =
            match notification_id_for_format(&interaction_data.notification_ids, format.id) {
                Some(notification_id) => notification_id.to_owned(),
                // TODO ONE-11754: remove once all access tokens issued before allocation of
                // notification ids in token endpoint have expired
                None => self
                    .transaction_manager
                    .tx(self.allocate_notification_id_tx(interaction_id, format.id))
                    .await
                    .error_while("allocating notification id")??,
            };

        match self
            .issue(holder_identifiers, credential, format, notification_id)
            .await
        {
            Ok(result) => {
                tracing::info!("Issued credential {}", credential.common().id);
                // errors stay plain JSON, only the successful response is encrypted
                self.encrypt_credential_response(result, request.credential_response_encryption)
                    .await
                    .map(|result| (result, dpop_nonce))
            }
            Err(error) => {
                let error = error.error_while("issuing credential");
                if credential.common().state == CredentialStateEnum::Offered {
                    self.transaction_manager
                        .tx(self.mark_issuance_failed_tx(credential.common().id, (&error).into()))
                        .await
                        .error_while("marking credential as failed")??;
                }

                Err(error.into())
            }
        }
    }

    /// Unwraps the Credential Request body, decrypting it when it arrived as a JWE.
    ///
    /// The JWE is addressed to one of the issuer keys published in the
    /// `credential_request_encryption` metadata parameter, selected by the `kid` header.
    async fn decrypt_credential_request(
        &self,
        request: CredentialRequestPayload,
        credential: &Credential,
        params: &OpenID4VCIFinal1Params,
    ) -> Result<CredentialRequest, OID4VCIFinal1_0ServiceError> {
        let jwe = match request {
            CredentialRequestPayload::Plain(request) => {
                if params.credential_endpoint_encryption.request_required {
                    tracing::info!("Rejecting unencrypted credential request: encryption required");
                    return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
                }
                return Ok(*request);
            }
            CredentialRequestPayload::Encrypted(jwe) => jwe,
        };

        let issuer_identifier = credential.issuer()?.data.identifier.as_ref().await?;

        let candidates = key_agreement_keys(
            &issuer_identifier,
            None,
            params.swiyu_mode,
            &*self.key_provider,
            &*self.key_algorithm_provider,
        )
        .await?;

        let requested_key_id = extract_jwe_header(&jwe)
            .map_err(|error| {
                tracing::info!("Failed parsing credential request JWE header: {error}");
                OpenID4VCIError::InvalidEncryptionParameters
            })?
            .key_id;

        let key = match &requested_key_id {
            Some(key_id) => candidates
                .into_iter()
                .find(|candidate| candidate.key.id.to_string() == *key_id),
            // the wallet did not name a key, so there must be no ambiguity about which one it used
            None => candidates.into_iter().exactly_one().ok(),
        }
            .ok_or_else(|| {
                tracing::info!(
                "No issuer key agreement key matching credential request JWE kid {requested_key_id:?}"
            );
                OpenID4VCIError::InvalidEncryptionParameters
            })?;

        let payload = decrypt_jwe(&jwe, &key.key, &*self.key_provider)
            .await
            .map_err(|error| {
                tracing::info!("Failed decrypting credential request: {error}");
                OpenID4VCIError::InvalidEncryptionParameters
            })?;

        serde_json::from_slice(&payload).map_err(|error| {
            tracing::info!("Failed parsing decrypted credential request: {error}");
            OpenID4VCIError::InvalidRequest.into()
        })
    }

    /// Encrypts the Credential Response when the wallet asked for it.
    ///
    /// The parameters were already checked by [`validate_response_encryption`].
    async fn encrypt_credential_response(
        &self,
        response: OpenID4VCICredentialResponseDTO,
        response_encryption: Option<ResponseEncryption>,
    ) -> Result<CredentialResponsePayload, OID4VCIFinal1_0ServiceError> {
        let Some(ResponseEncryption { jwk, enc, zip }) = response_encryption else {
            return Ok(CredentialResponsePayload::Plain(Box::new(response)));
        };

        let Some(alg) = jwk.alg() else {
            tracing::info!("Missing response encryption jwk alg value");
            return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
        };
        if alg != EncryptionKeyManagementAlgorithm::EcdhEs.to_string() {
            tracing::info!("Unsupported response encryption jwk alg value: `{alg}`",);
            return Err(OpenID4VCIError::InvalidEncryptionParameters.into());
        }

        let payload = serde_json::to_vec(&response).map_err(|error| {
            OID4VCIFinal1_0ServiceError::MappingError(format!(
                "Failed serializing credential response: {error}"
            ))
        })?;
        let jwe = build_jwe(
            &payload,
            &jwk,
            JweHeader {
                key_id: jwk.kid().map(String::from),
                zip,
                partyuinfo_data: None,
                partyvinfo_data: None,
            },
            enc,
            &*self.key_algorithm_provider,
        )
        .await
        .map_err(|error| {
            tracing::info!("Failed encrypting credential response: {error}");
            OpenID4VCIError::InvalidEncryptionParameters
        })?;

        Ok(CredentialResponsePayload::Encrypted(jwe))
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
        let nonce_id = validate_nonce(
            nonce_params.leeway_seconds,
            nonce_params.signing_key.clone(),
            self.base_url.as_ref(),
            &nonce,
            NonceContext::OpenID4VCINonce,
        )
        .map_err(|e| {
            tracing::debug!("Nonce validation failed: {e}");
            OpenID4VCIError::InvalidNonce
        })?
        .id;

        // Key attestation is expected if wallet storage type is set
        if let Some(key_storage_security) = schema.wallet_attestation.key_storage_security_level {
            let Some(key_attestation_jwt) = &key_attestation else {
                tracing::debug!("expected key attestation but none provided");
                return Err(OpenID4VCIError::InvalidOrMissingProof.into());
            };

            let ka = validator::validate_key_attestation(
                key_attestation_jwt,
                &token_verifier,
                key_storage_security.into(),
                params.key_attestation_leeway_seconds,
            )
            .await?;

            if schema.wallet_attestation.require_instance_attestation {
                let (Credential::IssuerSingle {
                    wallet_instance_attestation_blob_id: Some(wallet_instance_attestation_blob_id),
                    ..
                }
                | Credential::IssuerBatchParent {
                    wallet_instance_attestation_blob_id: Some(wallet_instance_attestation_blob_id),
                    ..
                }) = credential
                else {
                    tracing::debug!(
                        "instance attestation required but no wallet instance attestation blob ID found"
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
                        .map_err(|e| {
                        WalletAttestationError::WiaMalformed(format!("parsing stored WIA: {e}"))
                    })?;

                verify_ka_wia_issuers_match(&ka, &wia)?;
            }

            if interaction.ecosystem.is_some() {
                // committed, so the step validates the attestation and records the verdict
                self.ecosystem_resolver
                    .resolve(
                        interaction.id,
                        &[ProtocolArtifact::IssuerIssuance {
                            attestation: WalletAttestationArtifact::Key {
                                token: key_attestation_jwt,
                                jwt: &ka,
                            },
                            requirements: &schema.wallet_attestation,
                            credential_id: credential.common().id,
                        }],
                        None,
                    )
                    .await
                    .map_err(OID4VCIFinal1_0ServiceError::from_ecosystem_validation)?;
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

            if !ka.payload.custom.attested_keys.contains(&proof_signing_key) {
                tracing::debug!("proof signing key is not in the attested_keys list");
                return Err(OpenID4VCIError::InvalidOrMissingProof.into());
            }
        } else if key_attestation.is_some() {
            tracing::debug!("key attestation provided but not required, ignored");
        }

        let (identifier, key_id) = match holder_binding {
            OpenID4VCIProofHolderBinding::Did { did, key_id } => {
                let (identifier, _) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        schema.organisation.id(),
                        &IdentifierDetails::Did(did),
                        IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
                        true,
                        None,
                        None,
                    )
                    .await
                    .error_while("creating remote holder identifier")?;
                (identifier, key_id)
            }
            OpenID4VCIProofHolderBinding::Jwk(jwk) => {
                let (identifier, RemoteIdentifierRelation::Key(key)) = self
                    .identifier_creator
                    .get_or_create_remote_identifier(
                        schema.organisation.id(),
                        &IdentifierDetails::Key(jwk),
                        IdentifierName::PrefixForId(IdentifierRole::Holder.to_string()),
                        true,
                        None,
                        None,
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
            nonce_id,
        ))
    }

    /// Marks the credential as Error, unless it is no longer `Offered`: the failure might be
    /// a parallel request having issued it in the meantime, which must not be overwritten.
    async fn mark_issuance_failed_tx(
        &self,
        credential_id: CredentialId,
        error_info: HistoryErrorMetadata,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        let credential = self
            .credential_repository
            .lock_credential(&credential_id)
            .await
            .error_while("locking credential")?;
        if credential.common().state != CredentialStateEnum::Offered {
            return Ok(());
        }

        self.credential_repository
            .update_credential(
                credential_id,
                UpdateCredentialRequest {
                    state: Some(CredentialStateEnum::Error),
                    error_info: Some(error_info),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;
        Ok(())
    }

    /// Issues the credentials in memory and persists them in one short transaction at the end.
    /// Signing and reserving the status list entries happen before, outside of it.
    #[tracing::instrument(level = "debug", skip_all, err(level = "info"))]
    async fn issue(
        &self,
        mut holder_identifiers: Vec<PreparedIdentifier>,
        credential: &Credential,
        format: CredentialSchemaFormat,
        notification_id: String,
    ) -> Result<OpenID4VCICredentialResponseDTO, OID4VCIFinal1_0ServiceError> {
        let issuance_protocol = self
            .protocol_provider
            .get_protocol(&credential.common().protocol)?;
        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format.format)?;
        let format_default_expiration = formatter.get_default_expiration();

        let now = now_utc();
        let expires_at = credential.common().expires_at;
        let is_batch = credential
            .common()
            .schema
            .as_ref()
            .await?
            .batch_size
            .is_some();
        let format_type = self
            .config
            .format
            .get_type(&format.format)
            .error_while("getting format config")?;
        // Multiformat credentials also use batch parents. Only actual batches and MDOC
        // need the format's default validity; other items retain the parent expiry as-is.
        let batch_item_expires_at = if is_batch || format_type == FormatType::Mdoc {
            let default_expiry = now + format_default_expiration;
            Some(expires_at.map_or(default_expiry, |expiry| expiry.min(default_expiry)))
        } else {
            expires_at
        };
        let requested = RequestedFormat {
            format,
            format_type,
            is_batch,
        };

        // Signing persists nothing apart from the status list entries, which are reserved
        // without a link to the credential. If the issuance fails afterward, they are never
        // linked nor released. This is accepted: entries are cheap
        let credentials = match credential {
            Credential::IssuerSingle { .. } => {
                let holder = holder_identifiers
                    .pop()
                    .ok_or(OpenID4VCIError::InvalidOrMissingProof)?;
                // Only fails early here: validated again on the reloaded credential before
                // persisting, two parallel requests could both see the stale `Offered` state.
                self.validate_issuable(credential, &requested)?;
                let issued = issuance_protocol
                    .issuer_issue_credential(
                        credential.to_owned(),
                        requested.format.id,
                        holder.identifier,
                        holder.key_id,
                    )
                    .await
                    .error_while("issuing credential")?;
                let issued = PendingCredential {
                    issued,
                    key_attestation: holder.key_attestation,
                };
                let response = issued.response_entry();
                self.transaction_manager
                    .tx(self.persist_single_tx(issued, &requested, now))
                    .await
                    .error_while("persisting issued credential")??;
                vec![response]
            }
            Credential::IssuerBatchParent { common, .. } => {
                // All items of the batch are copies of the same template, so it is validated
                // once, before any item is issued. The template state is derived from the
                // latest issued item of the format (see `prepare_batch_item`).
                let template = self
                    .prepare_batch_item(
                        credential.to_owned(),
                        batch_item_expires_at,
                        &requested.format,
                    )
                    .await?;
                self.validate_issuable(&template, &requested)?;

                let mut items = Vec::with_capacity(holder_identifiers.len());
                for holder in holder_identifiers {
                    let mut item = template.clone();
                    item.common_mut().id = Uuid::new_v4().into();
                    let issued = issuance_protocol
                        .issuer_issue_credential(
                            item,
                            requested.format.id,
                            holder.identifier,
                            holder.key_id,
                        )
                        .await
                        .error_while("issuing credential")?;
                    items.push(PendingCredential {
                        issued,
                        key_attestation: holder.key_attestation,
                    });
                }
                let responses = items
                    .iter()
                    .map(PendingCredential::response_entry)
                    .collect();
                self.transaction_manager
                    .tx(self.persist_batch_tx(
                        common.id,
                        items,
                        &requested,
                        batch_item_expires_at,
                        now,
                    ))
                    .await
                    .error_while("persisting issued credentials")??;
                responses
            }
            _ => {
                return Err(OID4VCIFinal1_0ServiceError::MappingError(
                    "Invalid credential type".to_string(),
                ));
            }
        };

        Ok(OpenID4VCICredentialResponseDTO {
            redirect_uri: credential.common().redirect_uri.to_owned(),
            standard: CredentialResponse {
                credentials: Some(credentials),
                transaction_id: None,
                interval: None,
                notification_id: Some(notification_id),
            },
        })
    }

    fn validate_issuable(
        &self,
        credential: &Credential,
        requested: &RequestedFormat,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        validate_credential_issuable(
            credential,
            &requested.format.format,
            requested.format_type,
            requested.is_batch,
            &self.config,
        )
    }

    /// Persists an issued single credential, unless a concurrent request issued it in the meantime
    async fn persist_single_tx(
        &self,
        pending: PendingCredential,
        requested: &RequestedFormat,
        issuance_date: OffsetDateTime,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        let credential_id = pending.issued.credential.common().id;
        // Lock a single credential, so that it is issued only by one thread.
        // Loaded under the lock, a concurrent request might have issued it in the meantime
        let current = self
            .credential_repository
            .lock_credential(&credential_id)
            .await
            .error_while("locking credential")?;
        self.validate_issuable(&current, requested)?;

        let (credential_blob_id, wua_blob_id) = self
            .store_issued_blobs(
                &pending,
                current.issuer_credential()?.data.credential_blob_id,
            )
            .await?;
        self.credential_repository
            .update_credential(
                credential_id,
                issued_credential_update(
                    &pending.issued.credential,
                    credential_blob_id,
                    issuance_date,
                    wua_blob_id,
                )?,
            )
            .await
            .error_while("updating credential")?;

        self.link_revocation_entries(credential_id, pending.issued.unlinked_revocation_entries)
            .await
    }

    /// Persists the issued batch items and accepts the parent on its first issuance
    async fn persist_batch_tx(
        &self,
        parent_id: CredentialId,
        items: Vec<PendingCredential>,
        requested: &RequestedFormat,
        expires_at: Option<OffsetDateTime>,
        issuance_date: OffsetDateTime,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        // The parent is locked before inserting the items: their foreign key takes a shared lock
        // on it, upgrading that to update the parent deadlocks with a parallel issuance.
        // Different formats of one offer are still issued in parallel, only persisting is serialized.
        let parent = self
            .credential_repository
            .lock_credential(&parent_id)
            .await
            .error_while("locking parent credential")?;
        let parent_state = parent.common().state;
        // validated again under the lock, a concurrent request might have issued the format
        // in the meantime
        let template = self
            .prepare_batch_item(parent, expires_at, &requested.format)
            .await?;
        self.validate_issuable(&template, requested)?;

        if parent_state == CredentialStateEnum::Offered {
            self.credential_repository
                .update_credential(
                    parent_id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Accepted),
                        issuance_date: Some(issuance_date),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating parent credential")?;
        }

        let mut credentials = Vec::with_capacity(items.len());
        let mut revocation_entries = Vec::with_capacity(items.len());
        for item in items {
            let (credential_blob_id, wua_blob_id) = self.store_issued_blobs(&item, None).await?;
            let mut credential = item.issued.credential;
            let common = credential.common_mut();
            common.issuance_date = Some(issuance_date);
            common.last_modified = issuance_date;
            let data = credential.issuer_credential_mut()?.data;
            data.credential_blob_id = Some(credential_blob_id);
            data.wallet_key_attestation_blob_id = wua_blob_id;

            revocation_entries.push((
                credential.common().id,
                item.issued.unlinked_revocation_entries,
            ));
            credentials.push(credential);
        }
        self.credential_repository
            .create_credentials(credentials)
            .await
            .error_while("creating batch items")?;

        for (credential_id, entry_ids) in revocation_entries {
            self.link_revocation_entries(credential_id, entry_ids)
                .await?;
        }
        Ok(())
    }

    /// Stores the serialized credential, overwriting `credential_blob_id` if the credential
    /// already has one, and the wallet unit attestation of the holder
    async fn store_issued_blobs(
        &self,
        pending: &PendingCredential,
        credential_blob_id: Option<BlobId>,
    ) -> Result<(BlobId, Option<BlobId>), OID4VCIFinal1_0ServiceError> {
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let wua_blob_id = if let Some(attestation) = &pending.key_attestation {
            let wua_dto = serde_json::to_vec(&WalletUnitAttestationDTO {
                attestation: attestation.to_owned(),
            })
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

        let serialized_credential = &pending.issued.serialized_credential;
        let credential_blob_id = match credential_blob_id {
            None => {
                let blob = Blob::new(serialized_credential.as_ref(), BlobType::Credential);
                blob_storage
                    .create(blob.clone())
                    .await
                    .error_while("creating credential blob")?;
                blob.id
            }
            Some(blob_id) => {
                blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(serialized_credential.as_ref().into()),
                        },
                    )
                    .await
                    .error_while("updating credential blob")?;
                blob_id
            }
        };

        Ok((credential_blob_id, wua_blob_id))
    }

    /// Links the status list entries reserved while issuing to the persisted credential
    async fn link_revocation_entries(
        &self,
        credential_id: CredentialId,
        entry_ids: Vec<RevocationListEntryId>,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        for entry_id in entry_ids {
            self.revocation_list_repository
                .update_entry(
                    UpdateRevocationListEntryId::Id(entry_id),
                    UpdateRevocationListEntryRequest {
                        credential_id: Some(credential_id),
                        ..Default::default()
                    },
                )
                .await
                .error_while("linking revocation list entry")?;
        }
        Ok(())
    }

    /// Notification ids are allocated when issuing the token, tokens issued before that
    /// get the id of the requested format allocated here.
    async fn allocate_notification_id_tx(
        &self,
        interaction_id: InteractionId,
        format_id: CredentialSchemaFormatId,
    ) -> Result<String, OID4VCIFinal1_0ServiceError> {
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, Some(LockType::Update))
            .await
            .error_while("getting interaction")?;
        let mut interaction_data = interaction_data_to_dto(&interaction)?;

        // a concurrent request might have allocated it in the meantime
        if let Some(notification_id) =
            notification_id_for_format(&interaction_data.notification_ids, format_id)
        {
            return Ok(notification_id.to_owned());
        }

        let notification_id = generate_alphanumeric(32);
        interaction_data.notification_ids.push(FormatNotification {
            notification_id: notification_id.to_owned(),
            format: Some(format_id),
        });
        let data = serde_json::to_vec(&interaction_data)
            .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;

        self.interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    data: Some(Some(data)),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;

        Ok(notification_id)
    }

    /// The most recently created batch item of the format, `None` if the format was never issued
    async fn latest_batch_item(
        &self,
        parent_credential_id: CredentialId,
        format_id: CredentialSchemaFormatId,
    ) -> Result<Option<Credential>, OID4VCIFinal1_0ServiceError> {
        Ok(self
            .credential_repository
            .get_credential_list(ListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::ParentCredential(parent_credential_id).condition()
                        & CredentialFilterValue::FormatIds(vec![format_id])
                        & CredentialFilterValue::Deleted(false),
                ),
                sorting: Some(ListSorting {
                    column: SortableCredentialColumn::CreatedDate,
                    direction: Some(SortDirection::Descending),
                }),
                pagination: Some(ListPagination {
                    page: 0,
                    page_size: 1,
                }),
                ..Default::default()
            })
            .await
            .error_while("listing batch items")?
            .values
            .into_iter()
            .next())
    }

    async fn get_batch_items(
        &self,
        parent_credential_id: CredentialId,
    ) -> Result<Vec<Credential>, OID4VCIFinal1_0ServiceError> {
        Ok(self
            .credential_repository
            .get_credential_list(ListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::ParentCredential(parent_credential_id).condition()
                        & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                        & CredentialFilterValue::Deleted(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting batch items")?
            .values)
    }

    pub async fn handle_notification(
        &self,
        credential_schema_id: CredentialSchemaId,
        access_token: &str,
        dpop_proof: Option<&str>,
        request: NotificationRequest,
    ) -> Result<Option<DpopNonce>, OID4VCIFinal1_0ServiceError> {
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

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting credentials")?;

        let credentials: Vec<_> = credentials
            .into_iter()
            .filter(|credential| credential.common().schema.id() == credential_schema_id)
            .collect();
        let Some(credential) = credentials.first() else {
            return Err(OpenID4VCIError::InvalidNotificationRequest.into());
        };
        let dpop_nonce = self
            .validate_access_token_binding(
                interaction_id,
                interaction_data.dpop_jkt.as_deref(),
                access_token,
                dpop_proof,
                &credential.common().protocol,
                &format!("{credential_schema_id}/notification"),
            )
            .await?;

        // interactions created before multi-format support have a single entry without format
        let format_id = interaction_data
            .notification_ids
            .iter()
            .find(|entry| entry.notification_id == request.notification_id)
            .ok_or(OpenID4VCIError::InvalidNotificationId)?
            .format;

        let success_log = format!(
            "Processed notification event `{}`, description: `{:?}`, for credentials: [{}]",
            request.event,
            request.event_description,
            credentials.iter().map(|c| c.common().id).join(", ")
        );

        for credential in credentials {
            self.process_notification_for_credential(credential, format_id, &request)
                .await?;
        }

        tracing::info!(message = success_log);
        Ok(dpop_nonce)
    }

    pub async fn create_token(
        &self,
        credential_schema_id: &CredentialSchemaId,
        request: TokenRequest,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
        dpop_proof: Option<&str>,
    ) -> Result<(TokenResponse, Option<DpopNonce>), OID4VCIFinal1_0ServiceError> {
        let credential_schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let interaction_id = interaction_id_from_token_request(&request)?;
        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction_id)
            .await
            .error_while("getting credentials")?;

        // only batch_parent can be in state `Expiring`,
        // if it's the case, then any other credential related to specified interaction cannot be issued, or token cannot be refreshed
        if credentials
            .iter()
            .any(|c| c.common().state == CredentialStateEnum::Expiring)
        {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                CredentialStateEnum::Expiring,
            ));
        }

        let credential = credentials.first().ok_or(
            OID4VCIFinal1_0ServiceError::MissingCredentialsForInteraction { interaction_id },
        )?;

        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.common().protocol,
        )
        .error_while("validating protocol type")?;

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(&credential.common().protocol)
            .error_while("getting protocol params")?;

        let issuer_identifier_id = if params.swiyu_mode {
            None
        } else {
            Some(credential.issuer()?.data.identifier.id())
        };
        let client_attestation = self
            .validate_oauth_client_attestation(
                oauth_client_attestation,
                oauth_client_attestation_pop,
                dpop_proof.is_some(),
                &params,
                &credential_schema,
                credential,
                interaction_id,
                issuer_identifier_id,
            )
            .await?;

        // both refresh and access token have the same structure
        let generate_new_token =
            || SecretString::from(format!("{}.{}", interaction_id, generate_alphanumeric(32)));

        let pre_authorization_expires_in = get_issuance_param_pre_authorization_expires_in(
            &self.config,
            &credential.common().protocol,
        )
        .error_while("getting issuance params")?;
        let access_token_expires_in =
            get_issuance_param_token_expires_in(&self.config, &credential.common().protocol)
                .error_while("getting issuance params")?;
        let refresh_token_expires_in = get_issuance_param_refresh_token_expires_in(
            &self.config,
            &credential.common().protocol,
        )
        .error_while("getting issuance params")?;

        let tx: BoxFuture<Result<_, OID4VCIFinal1_0ServiceError>> = async {
            // Lock the interaction to ensure exclusive access
            let mut interaction = self
                .interaction_repository
                .get_interaction(&interaction_id, Some(LockType::Update))
                .await
                .error_while("getting interaction")?;
            let interaction_data = interaction_data_to_dto(&interaction)?;

            let dpop_binding = self
                .validate_token_key_binding(
                    interaction_id,
                    &interaction_data,
                    client_attestation.as_ref(),
                    dpop_proof,
                    &params,
                    &credential.common().protocol,
                    credential_schema_id,
                )
                .await?;
            // Consumed only after the DPoP proof was accepted: a request rejected with
            // `use_dpop_nonce` is repeated with the same Client Attestation PoP
            // https://www.rfc-editor.org/rfc/rfc9449.html#section-8
            if let Some(challenge_id) = client_attestation
                .as_ref()
                .and_then(|attestation| attestation.challenge_id)
            {
                self.consume_pop_challenge(interaction_id, challenge_id, &params)
                    .await?;
            }

            let mut response = oidc_issuer_create_token(
                &interaction_data,
                &convert_inner(credentials.to_owned()),
                &interaction,
                &request,
                pre_authorization_expires_in,
                access_token_expires_in,
                refresh_token_expires_in,
            )?;
            response.token_type = if dpop_binding.is_some() {
                TokenType::DPoP
            } else {
                TokenType::Bearer
            };

            let now = now_utc();

            for credential in &credentials {
                // If a wallet instance attestation token is provided, we create a new blob and update the credential
                let wallet_instance_attestation_blob_id = match client_attestation
                    .as_ref()
                    .map(|attestation| attestation.wallet_instance_attestation.to_owned())
                {
                    Some(wallet_instance_attestation_token) => {
                        let blob_storage = self
                            .blob_storage_provider
                            .get_blob_storage(BlobStorageType::Db)?;

                        let attestation_token = serde_json::to_vec(
                            &wallet_instance_attestation_token,
                        )
                        .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;

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
                        .update_credential(credential.common().id, state_update)
                        .await
                        .error_while("updating credential")?;
                }
            }

            let formats = offered_formats(&credential_schema, &interaction_data).await?;
            let mut offered_format_types = vec![];
            for format in &formats {
                offered_format_types.push(
                    self.config
                        .format
                        .get_type(&format.format)
                        .error_while("getting format config")?,
                );
            }

            // we add refresh token for mdoc and batches
            if offered_format_types.contains(&FormatType::Mdoc)
                || credential_schema.batch_size.is_some()
            {
                response.refresh_token = Some(generate_new_token());
                response.refresh_token_expires_in =
                    Some(ExpiresIn((now + refresh_token_expires_in).unix_timestamp()));
            }

            let mut new_interaction_data: OpenID4VCIIssuerInteractionDataDTO =
                (&response).try_into()?;
            new_interaction_data.formats = interaction_data.formats;
            new_interaction_data.notification_ids =
                allocate_notification_ids(interaction_data.notification_ids, &formats);
            new_interaction_data.dpop_jkt =
                dpop_binding.as_ref().map(|binding| binding.jkt.to_owned());
            // Only bound when enforced, so that enabling the enforcement binds ongoing issuances to
            // the key used on their next refresh
            new_interaction_data.client_instance_jkt = client_attestation
                .as_ref()
                .filter(|_| params.enforce_client_instance_binding)
                .map(|attestation| attestation.client_instance_jkt.to_owned());
            let data = serde_json::to_vec(&new_interaction_data)
                .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;
            interaction.data = Some(data);

            self.interaction_repository
                .update_interaction(interaction.id, interaction.into())
                .await
                .error_while("updating credential interaction")?;
            Ok((response, dpop_binding.and_then(|binding| binding.nonce)))
        }
        .boxed();
        let result = self
            .transaction_manager
            .tx(tx)
            .await
            .error_while("creating token")?;

        let (response, dpop_nonce) = match result {
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
                            credential.common().id,
                            UpdateCredentialRequest {
                                state: Some(CredentialStateEnum::Error),
                                error_info: Some(HistoryErrorMetadata {
                                    error_code: err.error_code(),
                                    message: format!(
                                        "Issuance failed while validating transaction code: {err}"
                                    ),
                                }),
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
            credential.common().id
        );
        Ok((response, dpop_nonce))
    }

    /// Validates the binding of the issued tokens to the keys of the client.
    ///
    /// Returns the validated DPoP proof if the issued tokens are DPoP bound.
    #[expect(clippy::too_many_arguments)]
    async fn validate_token_key_binding(
        &self,
        interaction_id: InteractionId,
        interaction_data: &OpenID4VCIIssuerInteractionDataDTO,
        client_attestation: Option<&ValidatedClientAttestation>,
        dpop_proof: Option<&str>,
        params: &OpenID4VCIFinal1Params,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<Option<ProofValidationOutput>, OID4VCIFinal1_0ServiceError> {
        // Refresh tokens are bound to the Client Instance they were issued to
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-10.3
        if params.enforce_client_instance_binding
            && let Some(bound_client_instance_jkt) = &interaction_data.client_instance_jkt
            && client_attestation.map(|attestation| &attestation.client_instance_jkt)
                != Some(bound_client_instance_jkt)
        {
            return Err(WalletAttestationError::ClientAttestationKeyMismatch.into());
        }

        // The DPoP key the issued tokens must be bound to:
        // * refreshed tokens stay bound to the key of the previous tokens, regardless of DPoP
        //   enforcement: https://www.rfc-editor.org/rfc/rfc9449.html#section-5-4
        // * in DPoP combined mode, the DPoP key is the Client Instance Key
        let bound_jkt = interaction_data.dpop_jkt.as_deref();
        let combined_mode_jkt = client_attestation
            .filter(|attestation| attestation.dpop_combined_mode)
            .map(|attestation| attestation.client_instance_jkt.as_str());
        let required_jkt = match (bound_jkt, combined_mode_jkt) {
            (Some(bound_jkt), Some(combined_mode_jkt)) if bound_jkt != combined_mode_jkt => {
                return Err(DpopHandlerError::KeyMismatch
                    .error_while("validating DPoP proof")
                    .into());
            }
            // bound_jkt is `None` on the initial token request, or on refreshing tokens previously
            // issued as Bearer (e.g. issued without DPoP proof or before DPoP was enabled):
            // In that case, combined mode then binds them to the client attestation PoP key, if any.
            (bound_jkt, combined_mode_jkt) => bound_jkt.or(combined_mode_jkt),
        };

        let dpop_enforced = params.dpop.as_ref().is_some_and(|dpop| dpop.enforced);
        match (dpop_proof, &params.dpop) {
            (Some(dpop_proof), Some(dpop_params)) => {
                let binding = self
                    .dpop_handler
                    .validate_proof(
                        interaction_id,
                        dpop_proof,
                        None,
                        self.expected_dpop_values(
                            protocol_id,
                            &format!("{credential_schema_id}/token"),
                            required_jkt,
                        )?,
                        map_dpop_params(
                            dpop_params.to_owned(),
                            self.base_url.clone(),
                            params.swiyu_mode,
                        ),
                    )
                    .await
                    .error_while("validating DPoP proof")?;
                Ok(Some(binding))
            }
            (_, None) if combined_mode_jkt.is_some() => Err(WalletAttestationError::WiaMalformed(
                "DPoP combined mode is not supported".to_string(),
            )
            .into()),
            _ if dpop_enforced || required_jkt.is_some() => {
                Err(OID4VCIFinal1_0ServiceError::DpopRequired)
            }
            // not DPoP bound, a submitted proof is ignored if DPoP is not supported
            _ => Ok(None),
        }
    }

    fn expected_dpop_values<'a>(
        &self,
        protocol_id: &str,
        endpoint: &str,
        jkt: Option<&'a str>,
    ) -> Result<ExpectedProofValues<'a>, OID4VCIFinal1_0ServiceError> {
        let base_url = self
            .protocol_provider
            .get_protocol(protocol_id)?
            .protocol_base_url()
            .ok_or(OID4VCIFinal1_0ServiceError::MappingError(
                "missing protocol_base_url".to_string(),
            ))?;
        let url = Url::parse(&format!("{base_url}/{endpoint}"))
            .map_err(|e| OID4VCIFinal1_0ServiceError::MappingError(e.to_string()))?;
        Ok(ExpectedProofValues {
            method: "POST",
            url,
            jkt,
        })
    }

    fn dpop_params(
        &self,
        protocol_id: &str,
    ) -> Result<Option<DpopParams>, OID4VCIFinal1_0ServiceError> {
        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(protocol_id)
            .error_while("getting protocol params")?;
        Ok(params
            .dpop
            .map(|p| map_dpop_params(p, self.base_url.clone(), params.swiyu_mode)))
    }

    async fn validate_access_token_binding(
        &self,
        interaction_id: InteractionId,
        jkt: Option<&str>,
        access_token: &str,
        dpop_proof: Option<&str>,
        protocol_id: &str,
        endpoint: &str,
    ) -> Result<Option<DpopNonce>, OID4VCIFinal1_0ServiceError> {
        let Some(params) = self.dpop_params(protocol_id)? else {
            return Ok(None);
        };
        // Already ongoing interactions are not validated against the protocol enforcement flag, but
        // rather the state of key binding.
        if jkt.is_none() {
            return Ok(None);
        };
        let proof = dpop_proof.ok_or(OID4VCIFinal1_0ServiceError::DpopRequired)?;
        let ProofValidationOutput { nonce, .. } = self
            .dpop_handler
            .validate_proof(
                interaction_id,
                proof,
                Some(access_token),
                self.expected_dpop_values(protocol_id, endpoint, jkt)?,
                params,
            )
            .await
            .error_while("validating DPoP proof")?;
        Ok(nonce)
    }

    #[expect(clippy::too_many_arguments)]
    async fn validate_oauth_client_attestation(
        &self,
        oauth_client_attestation: Option<&str>,
        oauth_client_attestation_pop: Option<&str>,
        dpop_proof_present: bool,
        params: &OpenID4VCIFinal1Params,
        credential_schema: &CredentialSchema,
        credential: &Credential,
        interaction_id: InteractionId,
        issuer_identifier_id: Option<IdentifierId>,
    ) -> Result<Option<ValidatedClientAttestation>, OID4VCIFinal1_0ServiceError> {
        // If the credential schema does not require client attestation, no tokens are expected
        if !credential_schema
            .wallet_attestation
            .require_instance_attestation
        {
            if oauth_client_attestation.is_some() || oauth_client_attestation_pop.is_some() {
                return Err(WalletAttestationError::WiaMalformed(
                    "unexpected OAuth client attestation headers".to_string(),
                )
                .into());
            }
            return Ok(None);
        }

        let wallet_instance_attestation_token = oauth_client_attestation.ok_or_else(|| {
            WalletAttestationError::WiaMalformed(
                "missing OAuth-Client-Attestation header".to_string(),
            )
        })?;

        let wallet_instance_attestation = Jwt::<WalletInstanceAttestationClaims>::decompose_token(
            wallet_instance_attestation_token,
        )
        .map_err(|e| WalletAttestationError::WiaMalformed(format!("parsing: {e}")))?;
        validate_timestamps(
            &wallet_instance_attestation,
            params.oauth_attestation_leeway_seconds,
        )?;
        let client_instance_jkt = client_instance_key_thumbprint(&wallet_instance_attestation)?;

        // In DPoP combined mode, the DPoP proof replaces the Client Attestation PoP and is
        // validated together with the key binding of the issued tokens
        // https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-12#section-7
        let (dpop_combined_mode, challenge_id) = match oauth_client_attestation_pop {
            Some(proof_of_key_possession_token) => {
                let challenge_id = self
                    .validate_oauth_client_attestation_pop(
                        proof_of_key_possession_token,
                        &wallet_instance_attestation,
                        params,
                        credential_schema,
                        credential,
                        issuer_identifier_id,
                    )
                    .await?;
                (false, challenge_id)
            }
            None if dpop_proof_present => (true, None),
            None => {
                return Err(WalletAttestationError::WiaMalformed(
                    "missing OAuth-Client-Attestation-PoP header".to_string(),
                )
                .into());
            }
        };

        // Validate WIA
        let verifier = KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        };
        verify_wia_signature(&wallet_instance_attestation, &verifier).await?;

        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("getting interaction")?;
        if interaction.ecosystem.is_some() {
            // committed, so the step validates the attestation and records the verdict
            self.ecosystem_resolver
                .resolve(
                    interaction.id,
                    &[ProtocolArtifact::IssuerIssuance {
                        attestation: WalletAttestationArtifact::WalletInstance {
                            token: wallet_instance_attestation_token,
                            jwt: &wallet_instance_attestation,
                        },
                        requirements: &credential_schema.wallet_attestation,
                        credential_id: credential.common().id,
                    }],
                    None,
                )
                .await
                .map_err(OID4VCIFinal1_0ServiceError::from_ecosystem_validation)?;
        }

        // Extract wallet metadata
        let (name, link) = extract_wallet_metadata(&wallet_instance_attestation)?;

        Ok(Some(ValidatedClientAttestation {
            wallet_instance_attestation: WalletInstanceAttestationDTO {
                name,
                link,
                attestation: wallet_instance_attestation_token.to_owned(),
            },
            client_instance_jkt,
            dpop_combined_mode,
            challenge_id,
        }))
    }

    /// Returns the id of the attestation challenge, to be consumed once the request is accepted.
    async fn validate_oauth_client_attestation_pop(
        &self,
        proof_of_key_possession_token: &str,
        wallet_instance_attestation: &DecomposedJwt<WalletInstanceAttestationClaims>,
        params: &OpenID4VCIFinal1Params,
        credential_schema: &CredentialSchema,
        credential: &Credential,
        issuer_identifier_id: Option<IdentifierId>,
    ) -> Result<Option<NonceId>, OID4VCIFinal1_0ServiceError> {
        let proof_of_key_possession =
            Jwt::<OAuthClientAttestationPopCustomClaims>::decompose_token(
                proof_of_key_possession_token,
            )
            .map_err(|e| {
                WalletAttestationError::WiaMalformed(format!("parsing client attestation PoP: {e}"))
            })?;
        validate_timestamps(
            &proof_of_key_possession,
            params.oauth_attestation_leeway_seconds,
        )?;

        let expected_audience = {
            let issuance_protocol = self
                .protocol_provider
                .get_protocol(&credential.common().protocol)?;
            let base_url = issuance_protocol.protocol_base_url().ok_or(
                OID4VCIFinal1_0ServiceError::MappingError("missing protocol_base_url".to_string()),
            )?;
            let protocol_id = &credential.common().protocol;
            let credential_schema_id = credential_schema.id;
            if let Some(issuer_identifier_id) = issuer_identifier_id {
                format!("{base_url}/{protocol_id}/{issuer_identifier_id}/{credential_schema_id}")
            } else {
                format!("{base_url}/{protocol_id}/{credential_schema_id}")
            }
        };
        validate_pop_audience(&proof_of_key_possession, &expected_audience)?;
        validate_pop_issuer(&proof_of_key_possession, wallet_instance_attestation)?;
        verify_pop_signature(
            &proof_of_key_possession,
            wallet_instance_attestation,
            self.key_algorithm_provider.as_ref(),
        )?;
        self.validate_pop_challenge(&proof_of_key_possession.payload.custom, params)
            .await
    }

    pub async fn generate_nonce(
        &self,
        protocol_id: &str,
    ) -> Result<NonceResponse, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )
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

        let c_nonce = generate_nonce(
            params.expiration_seconds,
            params.signing_key,
            self.base_url.to_owned(),
            NonceContext::OpenID4VCINonce,
        )
        .await
        .error_while("generating nonce")?;
        Ok(NonceResponse { c_nonce })
    }

    pub async fn generate_oauth_attestation_challenge(
        &self,
        protocol_id: &str,
    ) -> Result<ChallengeResponse, OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            protocol_id,
        )
        .error_while("validating protocol type")?;

        let params: OpenID4VCIFinal1Params = self
            .config
            .issuance_protocol
            .get(protocol_id)
            .error_while("getting protocol params")?;
        let Some(params) = params.oauth_attestation_challenge else {
            return Err(ConfigValidationError::TypeNotFound(protocol_id.to_string())
                .error_while("getting oauth attestation challenge params")
                .into());
        };

        let attestation_challenge = generate_nonce(
            params.expiration_seconds,
            params.signing_key,
            self.base_url.to_owned(),
            NonceContext::OAuthAttestationChallenge,
        )
        .await
        .error_while("generating attestation challenge")?;
        Ok(ChallengeResponse {
            attestation_challenge,
        })
    }

    async fn prepare_batch_item(
        &self,
        parent_credential: Credential,
        expires_at: Option<OffsetDateTime>,
        format: &CredentialSchemaFormat,
    ) -> Result<Credential, OID4VCIFinal1_0ServiceError> {
        let now = crate::clock::now_utc();
        let parent_credential_id = parent_credential.common().id;

        // `validate_credential_issuable` decides by the item state:
        // Offered -> initial issuance, Accepted -> refresh (MSO refresh for mdoc, new batch with batch size, otherwise BR_0483)
        // the parent is Accepted once any format was issued, so the first item of a format starts as Offered
        let latest_item = self
            .latest_batch_item(parent_credential_id, format.id)
            .await?;
        let state = match latest_item {
            Some(_) => parent_credential.common().state,
            None => CredentialStateEnum::Offered,
        };

        let Credential::IssuerBatchParent {
            mut common, issuer, ..
        } = parent_credential
        else {
            return Err(DataLayerError::MappingError(anyhow::anyhow!(
                "Expected an issuer batch parent credential"
            ))
            .error_while("preparing issuer batch item")
            .into());
        };
        common.id = Uuid::new_v4().into();
        common.created_date = now;
        // mdoc refreshes are rate-limited by last_modified: measured from the previous
        // issuance of the format, the parent is only updated by the first issuance.
        // The copied value is temporary: the update after issuing the item bumps last_modified to now
        if let Some(latest_item) = latest_item {
            common.last_modified = latest_item.common().last_modified;
        }
        common.issuance_date = Some(now);
        common.interaction = None;
        common.expires_at = expires_at;
        common.state = state;
        Ok(Credential::IssuerBatchItem {
            common,
            issuer,
            parent: Related::new(parent_credential_id, self.credential_repository.clone()),
            credential: IssuerCredentialData {
                format: format.to_owned().into(),
                holder_identifier: None,
                credential_blob_id: None,
                wallet_key_attestation_blob_id: None,
            },
        })
    }

    async fn process_notification_for_credential(
        &self,
        credential: Credential,
        format_id: Option<CredentialSchemaFormatId>,
        notification: &NotificationRequest,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        validate_issuance_protocol_type(
            IssuanceProtocolType::OpenId4VciFinal1_0,
            &self.config,
            &credential.common().protocol,
        )
        .error_while("validating protocol type")?;

        match (credential.common().state, &notification.event) {
            (
                CredentialStateEnum::Accepted
                | CredentialStateEnum::Suspended { .. }
                | CredentialStateEnum::Revoked,
                _,
            ) => {
                // ok, can be processed
            }
            // repeated requests also allowed
            (CredentialStateEnum::Error, NotificationEvent::CredentialFailure)
            | (CredentialStateEnum::Rejected, NotificationEvent::CredentialDeleted) => {}
            // anything else is invalid
            _ => {
                return Err(OpenID4VCIError::InvalidNotificationRequest.into());
            }
        };

        let new_state = match notification.event {
            NotificationEvent::CredentialAccepted => None,
            NotificationEvent::CredentialFailure => Some(CredentialStateEnum::Error),
            NotificationEvent::CredentialDeleted => Some(CredentialStateEnum::Rejected),
        };
        let error_info = (notification.event == NotificationEvent::CredentialFailure).then(|| {
            let mut message = "Wallet reported credential_failure".to_string();
            if let Some(description) = &notification.event_description
                && !description.as_str().is_empty()
            {
                message.push_str(": ");
                message.push_str(description.as_str());
            }
            HistoryErrorMetadata {
                error_code: ErrorCode::BR_0048,
                message,
            }
        });

        match (&credential, format_id) {
            (
                Credential::IssuerBatchParent { .. } | Credential::HolderBatchParent { .. },
                Some(format_id),
            ) => {
                self.process_notification_for_batch_format(
                    credential, format_id, new_state, error_info,
                )
                .await
            }
            _ => {
                if let Some(new_state) = new_state {
                    self.update_notified_credential(credential, new_state, error_info)
                        .await?;
                }
                Ok(())
            }
        }
    }

    async fn process_notification_for_batch_format(
        &self,
        parent: Credential,
        format_id: CredentialSchemaFormatId,
        new_state: Option<CredentialStateEnum>,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        let (affected, others): (Vec<_>, Vec<_>) = self
            .get_batch_items(parent.common().id)
            .await?
            .into_iter()
            .partition(|item| match item {
                Credential::IssuerBatchItem { credential, .. } => {
                    credential.format.id() == format_id
                }
                Credential::HolderBatchItem { credential, .. } => {
                    credential.format.id() == format_id
                }
                _ => false,
            });

        if affected.is_empty() {
            return Err(OpenID4VCIError::InvalidNotificationRequest.into());
        }
        let Some(new_state) = new_state else {
            return Ok(());
        };

        for item in affected {
            if item.common().state != new_state {
                self.update_notified_credential(item, new_state, error_info.clone())
                    .await?;
            }
        }

        let other_format_active = others.iter().any(|item| {
            matches!(
                item.common().state,
                CredentialStateEnum::Accepted | CredentialStateEnum::Suspended { .. }
            )
        });
        if !other_format_active && parent.common().state != new_state {
            self.credential_repository
                .update_credential(
                    parent.common().id,
                    UpdateCredentialRequest {
                        state: Some(new_state),
                        error_info,
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating parent credential")?;
        }

        Ok(())
    }

    async fn update_notified_credential(
        &self,
        credential: Credential,
        new_state: CredentialStateEnum,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        if credential.common().state == new_state {
            // nothing to do
            return Ok(());
        }

        let schema = credential.common().schema.as_ref().await?;

        let format = match &credential {
            Credential::IssuerSingle { credential, .. }
            | Credential::IssuerBatchItem { credential, .. } => Some(&credential.format),
            Credential::HolderSingle { credential, .. }
            | Credential::HolderBatchItem { credential, .. } => Some(&credential.format),
            Credential::Verifier { verifier_data, .. } => Some(&verifier_data.format),
            Credential::IssuerBatchParent { .. } | Credential::HolderBatchParent { .. } => None,
        };
        let revocation_method = match format {
            Some(format) => {
                let format = format.as_ref().await?;
                let formatter = self
                    .formatter_provider
                    .get_credential_formatter(&format.format)?;
                match schema.revocation_method_id(formatter.as_ref()) {
                    Some(method_id) => Some(
                        self.revocation_method_provider
                            .get_revocation_method(method_id)?,
                    ),
                    None => None,
                }
            }
            None => None,
        };

        self.credential_repository
            .update_credential(
                credential.common().id,
                UpdateCredentialRequest {
                    state: Some(new_state),
                    error_info,
                    ..Default::default()
                },
            )
            .await
            .error_while("updating credential")?;

        // mark the credential as revoked (if supported and not done before)
        if matches!(
            credential.common().state,
            CredentialStateEnum::Accepted | CredentialStateEnum::Suspended { .. }
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
        if credential.common().state.is_terminal() {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.common().state,
            ));
        }
        if credential.common().state == CredentialStateEnum::Expiring {
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.common().state,
            ));
        }
        if is_batch_parent_expired(credential, Some(interaction), now_utc())
            .error_while("checking credential state")?
        {
            self.credential_repository
                .update_credential(
                    credential.common().id,
                    UpdateCredentialRequest {
                        state: Some(CredentialStateEnum::Expired),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating expired credential")?;
            return Err(OID4VCIFinal1_0ServiceError::InvalidCredentialState(
                credential.common().state,
            ));
        }
        Ok(())
    }

    /// Validates the attestation challenge without consuming it, see
    /// [`Self::consume_pop_challenge`].
    async fn validate_pop_challenge(
        &self,
        pop_token_claims: &OAuthClientAttestationPopCustomClaims,
        params: &OpenID4VCIFinal1Params,
    ) -> Result<Option<NonceId>, OID4VCIFinal1_0ServiceError> {
        let Some(challenge_params) = &params.oauth_attestation_challenge else {
            return Ok(None);
        };

        let Some(challenge) = &pop_token_claims.challenge else {
            return Err(WalletAttestationError::MissingChallenge {
                fresh_challenge: self.fresh_attestation_challenge(challenge_params).await?,
            }
            .into());
        };

        match validate_nonce(
            challenge_params.leeway_seconds,
            challenge_params.signing_key.clone(),
            self.base_url.as_ref(),
            challenge,
            NonceContext::OAuthAttestationChallenge,
        ) {
            Ok(info) => Ok(Some(info.id)),
            Err(err) => Err(WalletAttestationError::InvalidChallenge {
                fresh_challenge: self.fresh_attestation_challenge(challenge_params).await?,
            }
            .error_while(format!("OAuth attestation challenge validation: {err}"))
            .into()),
        }
    }

    /// Marks a validated attestation challenge as used, rejecting replays.
    async fn consume_pop_challenge(
        &self,
        interaction_id: InteractionId,
        challenge_id: NonceId,
        params: &OpenID4VCIFinal1Params,
    ) -> Result<(), OID4VCIFinal1_0ServiceError> {
        let Err(err) = self
            .interaction_repository
            .mark_nonces_as_used(&interaction_id, vec![challenge_id])
            .await
        else {
            return Ok(());
        };
        Err(match (err, &params.oauth_attestation_challenge) {
            (DataLayerError::AlreadyExists(_), Some(challenge_params)) => {
                WalletAttestationError::InvalidChallenge {
                    fresh_challenge: self.fresh_attestation_challenge(challenge_params).await?,
                }
                .into()
            }
            (e, _) => e.error_while("marking challenge as used").into(),
        })
    }

    async fn fresh_attestation_challenge(
        &self,
        params: &OpenID4VCNonceParams,
    ) -> Result<String, OID4VCIFinal1_0ServiceError> {
        Ok(generate_nonce(
            params.expiration_seconds,
            params.signing_key.to_owned(),
            self.base_url.clone(),
            NonceContext::OAuthAttestationChallenge,
        )
        .await
        .error_while("generating fresh attestation challenge")?)
    }

    pub async fn generate_dpop_nonce(&self, protocol: ProtocolSelection) -> Option<DpopNonce> {
        let protocol = match protocol {
            ProtocolSelection::ProtocolId(id) => id,
            ProtocolSelection::AccessToken(access_token) => {
                let interaction_id = parse_access_token(&access_token)
                    .inspect_err(|err| tracing::warn!("Failed to parse access token: {err}"))
                    .ok()?;
                self.protocol_from_interaction_lenient(&interaction_id)
                    .await?
            }
            ProtocolSelection::TokenRequest(request) => {
                let interaction_id = interaction_id_from_token_request(&request)
                    .inspect_err(|err| tracing::warn!("Failed to parse token request: {err}"))
                    .ok()?;
                self.protocol_from_interaction_lenient(&interaction_id)
                    .await?
            }
        };
        let params = self
            .dpop_params(&protocol)
            .inspect_err(|err| tracing::warn!("Failed to collect DPoP params: {err}"))
            .ok()??;
        self.dpop_handler
            .generate_nonce(params)
            .await
            .inspect_err(|err| tracing::warn!("Failed to generate DPoP nonce: {err}"))
            .ok()
    }

    async fn protocol_from_interaction_lenient(
        &self,
        interaction_id: &InteractionId,
    ) -> Option<String> {
        let credential = self
            .credential_repository
            .get_credentials_by_interaction_id(interaction_id)
            .await
            .inspect_err(|err| {
                tracing::warn!("Failed to load credentials for interaction {interaction_id}: {err}")
            })
            .ok()
            .and_then(|mut v| v.pop())?;
        Some(credential.common().protocol.clone())
    }
}

/// Swiss Profile header claims for a protocol with the given params.
///
/// Spec: Swiss Profile for Issuance, Sections 12.2.3 and 12.3
/// <https://swiyu-admin-ch.github.io/specifications/swiss-profile-issuance/#1223-signed-metadata>
fn swiss_profile_header(params: &OpenID4VCIFinal1Params) -> SwissProfileHeader {
    SwissProfileHeader {
        profile_version: params
            .swiyu_mode
            .then(|| SWISS_PROFILE_ISSUANCE_VERSION.to_string()),
    }
}

struct PreparedIdentifier {
    identifier: Identifier,
    key_id: String,
    key_attestation: Option<String>,
}

/// The format requested to issue, as checked by `validate_credential_issuable`
struct RequestedFormat {
    format: CredentialSchemaFormat,
    format_type: FormatType,
    is_batch: bool,
}

/// A credential issued in memory, waiting to be persisted
struct PendingCredential {
    issued: IssuedCredential,
    key_attestation: Option<String>,
}

impl PendingCredential {
    fn response_entry(&self) -> CredentialResponseEntry {
        CredentialResponseEntry {
            credential: self.issued.serialized_credential.to_owned().into(),
        }
    }
}

struct ValidatedClientAttestation {
    wallet_instance_attestation: WalletInstanceAttestationDTO,
    /// JWK SHA-256 thumbprint of the Client Instance Key
    client_instance_jkt: String,
    /// The DPoP proof serves as the Client Attestation PoP
    dpop_combined_mode: bool,
    /// Attestation challenge of the Client Attestation PoP, not yet consumed
    challenge_id: Option<NonceId>,
}
