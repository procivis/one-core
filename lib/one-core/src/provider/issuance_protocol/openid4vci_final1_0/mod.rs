//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

use std::collections::{HashMap, HashSet};
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use attestations::requires_wia;
use indexmap::IndexMap;
use itertools::Itertools;
use mapper::{
    credential_config_to_holder_signing_algs_and_key_storage_security, get_credential_offer_url,
    intersect_supported, map_cryptographic_binding_methods_supported, map_proof_types_supported,
    parse_credential_issuer_params,
};
use model::{
    HolderBinding, HolderCredentialConfiguration, HolderInteractionData, OpenID4VCIFinal1Params,
    OpenID4VCIIssuerInteractionDataDTO, PreparedMetadata, RequestedCredential,
    TokenRequestAttestationHeaders,
};
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::jwe::{Header as JweHeader, decrypt_jwe_payload};
use proc_macros::Provider;
use proof_formatter::{OpenID4VCIProofJWTFormatter, PublicKeyInfo};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use service::{
    build_issuer_display, create_credential_offer, create_issuer_metadata_response,
    credential_configuration_supported, get_protocol_base_url,
};
use shared_types::{
    BlobId, CredentialFormat, CredentialId, CredentialSchemaFormatId, CredentialSchemaId,
    IdentifierId, InteractionId, OrganisationId, SerializedCredential,
};
use standardized_types::iana::{EncryptionAlgorithm, EncryptionKeyManagementAlgorithm};
use standardized_types::jwe::CompressionAlgorithm;
use standardized_types::jwk::{JwkUse, Jwks};
use standardized_types::oauth2::attestation_based_client_auth::ChallengeResponse;
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::token::{
    TokenErrorCode, TokenErrorResponse, TokenRequest, TokenResponse,
};
use standardized_types::openid4vci::{
    AuthorizationCodeGrant, AuthorizationDetail, CredentialConfiguration, CredentialIssuerMetadata,
    CredentialOffer, CredentialRequest, CredentialRequestEncryption, CredentialRequestIdentifier,
    CredentialResponseEncryption, Grants, IssuerInfoAttestation, IssuerInfoAttestationFormat,
    NonceResponse, NotificationEvent, NotificationRequest, ProofTypeSupported, Proofs,
    ResponseEncryption,
};
use standardized_types::openid4vp::dcql::CredentialQueryId;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::{OpenIDIssuanceError, TxCodeError};
use super::mapper::{
    autogenerate_holder_binding, generate_transaction_code, get_issued_credential_update,
    interaction_from_handle_invitation,
};
use super::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, IssuanceAcceptResponse,
    IssuanceAcceptResult, IssuanceRefreshResponse, ShareResponse, SubmitIssuerResponse,
};
use super::{
    HolderBindingInput, IssuanceProtocol, IssuanceProtocolError, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::clock::now_utc;
use crate::config::core_config::{
    BlobStorageType, CoreConfig, DidType as ConfigDidType, FormatType, KeyAlgorithmType,
};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::mapper::openid4vp::format_type_to_dcql_format;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialStateEnum, CredentialType,
};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::did::KeyRole;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::key::Key;
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::{ListPagination, ListQuery};
use crate::model::organisation::Organisation;
use crate::model::relation::{OptionalRelatedExt, Related};
use crate::model::wallet_attestation::AttestationType;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::http_client::{HttpClient, Response, is_media_type};
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::session_provider::SessionProvider;
use crate::proto::swiyu_http_client::ProxySwiyuHttpClient;
use crate::proto::transaction_manager::TransactionManager;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::mapper::{first_certificate, unsigned_credential};
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{CredentialData, VerificationFn};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::key_algorithm::ecdsa::ecdsa_public_key_as_jwk;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::model::Features as KeyAlgorithmFeatures;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::wallet_attestation_repository::WalletAttestationRepository;
use crate::service::oid4vci_final1_0::dto::OpenID4VCICredentialResponseDTO;
use crate::util::jwe::{build_jwe, select_recipient_jwk};
use crate::util::key_agreement::{KeyAgreementKey, key_agreement_keys};
use crate::util::key_selection::KeyFilter;

mod attestations;
mod holder_credentials;
pub(crate) mod mapper;
pub mod model;
pub mod proof_formatter;
pub mod service;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_issuance;
pub mod validator;

const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";

#[derive(Provider)]
pub(crate) struct OpenID4VCIFinal1_0 {
    client: Arc<dyn HttpClient>,
    metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
    base_url: Option<String>,
    protocol_base_url: Option<String>,
    config: Arc<CoreConfig>,
    params: OpenID4VCIFinal1Params,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    config_id: String,
    holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
    holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
    certificate_validator: Arc<dyn CertificateValidator>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
    identifier_repository: Arc<dyn IdentifierRepository>,
    did_repository: Arc<dyn DidRepository>,
    wallet_attestation_repository: Arc<dyn WalletAttestationRepository>,
    tx_manager: Arc<dyn TransactionManager>,
}

fn should_create_batch_parent(
    response: &IssuanceAcceptResponse,
    has_multiple_configurations: bool,
    has_refresh_token: bool,
    advertised_batch_size: Option<u32>,
    any_batch_issued: bool,
) -> bool {
    // The actual response and advertised batch size can differ. A real batch always
    // needs a parent; a single credential needs one only if it can expire.
    if !response.batch_items.is_empty() {
        return true;
    }

    has_multiple_configurations
        && response.main_credential.credential.expires_at.is_some()
        && (has_refresh_token
            || advertised_batch_size.is_some_and(|size| size > 1)
            || any_batch_issued)
}

impl OpenID4VCIFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        credential_schema_importer: Arc<dyn CredentialSchemaImporter>,
        credential_schema_repository: Arc<dyn CredentialSchemaRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        key_security_level_provider: Arc<dyn KeySecurityLevelProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: serde_json::Value,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        did_repository: Arc<dyn DidRepository>,
        wallet_attestation_repository: Arc<dyn WalletAttestationRepository>,
        tx_manager: Arc<dyn TransactionManager>,
    ) -> Result<Self, InitializationError> {
        let params: OpenID4VCIFinal1Params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        let protocol_base_url = base_url
            .as_ref()
            .map(|url| get_protocol_base_url(url, params.swiyu_mode));
        let client = if params.swiyu_mode {
            Arc::new(ProxySwiyuHttpClient { client }) as _
        } else {
            client
        };
        Ok(Self {
            client,
            metadata_cache,
            credential_repository,
            key_repository,
            identifier_creator,
            credential_schema_importer,
            credential_schema_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            blob_storage_provider,
            config_id,
            holder_wallet_unit_proto,
            holder_wallet_unit_repository,
            key_security_level_provider,
            certificate_validator,
            history_repository,
            session_provider,
            interaction_repository,
            identifier_repository,
            did_repository,
            wallet_attestation_repository,
            tx_manager,
        })
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        format: &CredentialFormat,
        format_type: FormatType,
        supports_batch_issuance: bool,
    ) -> Result<(), IssuanceProtocolError> {
        match (latest_state, format_type) {
            (CredentialStateEnum::Accepted, FormatType::Mdoc) if !supports_batch_issuance => {
                // mdoc MSO refresh -> rate-limiting by mso_minimum_refresh_time
                let credential = self
                    .credential_repository
                    .get_credential(credential_id)
                    .await
                    .error_while("getting credential")?;

                let can_be_updated_at =
                    credential.last_modified + self.mso_minimum_refresh_time(format)?;

                if can_be_updated_at > now_utc() {
                    return Err(IssuanceProtocolError::RefreshTooSoon);
                }
            }
            (CredentialStateEnum::Suspended, FormatType::Mdoc) => {
                return Err(IssuanceProtocolError::Suspended);
            }
            (CredentialStateEnum::Offered, _) => {
                // initial issuance -> OK
            }
            (CredentialStateEnum::Accepted, _) if supports_batch_issuance => {
                // batch re-issuance -> OK
            }
            (CredentialStateEnum::Accepted, _) => {
                return Err(IssuanceProtocolError::FormatRefreshNotSupported(
                    format.to_owned(),
                ));
            }
            _ => {
                return Err(IssuanceProtocolError::InvalidRequest(
                    "invalid state".to_string(),
                ));
            }
        }

        Ok(())
    }

    fn mso_minimum_refresh_time(
        &self,
        format: &CredentialFormat,
    ) -> Result<Duration, IssuanceProtocolError> {
        Ok(self
            .config
            .format
            .get::<mdoc_formatter::Params, _>(format)
            .map(|p| p.mso_minimum_refresh_seconds)
            .error_while("getting format params")?)
    }

    async fn jwk_key_id_from_identifier(
        &self,
        issuer_identifier: &Identifier,
        key: &Key,
    ) -> Result<Option<String>, IssuanceProtocolError> {
        let IdentifierData::Did(did) = &issuer_identifier.data else {
            return Ok(None);
        };
        let did = did.as_ref().await?;

        let related_did_key = did
            .find_key(&key.id, &KeyFilter::did_role(KeyRole::AssertionMethod))
            .await
            .error_while("finding related key")?;
        let issuer_jwk_key_id = did.verification_method_id(&related_did_key);

        Ok(Some(issuer_jwk_key_id))
    }

    async fn holder_fetch_token(
        &self,
        interaction_data: &HolderInteractionData,
        tx_code: Option<String>,
        wallet_attestation_request: Option<TokenRequestAttestationHeaders>,
    ) -> Result<TokenResponse, IssuanceProtocolError> {
        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let grants = interaction_data
            .grants
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "grants data is missing".to_string(),
            ))?;

        let has_sent_tx_code = tx_code.is_some();

        let form = match grants {
            Grants::PreAuthorizedCode(code) => TokenRequest::PreAuthorizedCode {
                pre_authorized_code: code.pre_authorized_code.to_owned(),
                tx_code,
            },
            Grants::AuthorizationCode(_) => {
                let Some(data) = &interaction_data.continue_issuance else {
                    return Err(IssuanceProtocolError::Failed(
                        "continue_issuance data is missing".to_string(),
                    ));
                };
                TokenRequest::AuthorizationCode {
                    authorization_code: data.authorization_code.to_owned(),
                    client_id: data.client_id.to_owned(),
                    redirect_uri: data.redirect_uri.to_owned(),
                    code_verifier: data.code_verifier.to_owned(),
                }
            }
        };

        let mut request = self
            .client
            .post(token_endpoint.as_str())
            .form(&form)
            .error_while("preparing token request")?;

        if let Some(wallet_attestation_request) = wallet_attestation_request {
            request = request
                .header(
                    "OAuth-Client-Attestation",
                    &wallet_attestation_request.wallet_attestation,
                )
                .header(
                    "OAuth-Client-Attestation-PoP",
                    &wallet_attestation_request.wallet_attestation_pop,
                );
        }

        let response = request.send().await.error_while("requesting token")?;

        if response.status.is_client_error() && has_sent_tx_code {
            match serde_json::from_slice::<TokenErrorResponse>(&response.body).map(|r| r.error) {
                Ok(TokenErrorCode::InvalidGrant) => {
                    return Err(TxCodeError::IncorrectCode
                        .error_while("checking TX response")
                        .into());
                }
                Ok(TokenErrorCode::InvalidRequest) => {
                    return Err(TxCodeError::InvalidCodeUse
                        .error_while("checking TX response")
                        .into());
                }
                Ok(_) | Err(_) => {}
            }
        }

        Ok(response
            .error_for_status()
            .error_while("requesting token")?
            .json()
            .error_while("requesting token")?)
    }

    async fn holder_reuse_or_refresh_token(
        &self,
        interaction_id: InteractionId,
        organisation_id: OrganisationId,
        interaction_data: &mut HolderInteractionData,
    ) -> Result<SecretString, IssuanceProtocolError> {
        let now = now_utc();
        if let Some(encrypted_token) = &interaction_data.access_token {
            let token_valid = interaction_data
                .access_token_expires_at
                .map(|v| v > now)
                .unwrap_or(true);
            if token_valid {
                let access_token = decrypt_string(encrypted_token, &self.params.encryption)
                    .map_err(|err| {
                        IssuanceProtocolError::Failed(format!(
                            "failed to decrypt access token: {err}"
                        ))
                    })?;
                return Ok(access_token);
            }
        }

        // Fetch a new one
        let refresh_token = if let Some(refresh_token) = interaction_data.refresh_token.as_ref() {
            decrypt_string(refresh_token, &self.params.encryption).map_err(|err| {
                IssuanceProtocolError::Failed(format!("failed to decrypt refresh token: {err}"))
            })?
        } else {
            tracing::info!("No refresh token");
            return Err(IssuanceProtocolError::RefreshNotPossible);
        };

        if interaction_data
            .refresh_token_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            tracing::info!("Refresh token expired");
            return Err(IssuanceProtocolError::RefreshNotPossible);
        }

        // Refresh the WIA
        // https://drafts.oauth.net/draft-ietf-oauth-attestation-based-client-auth/draft-ietf-oauth-attestation-based-client-auth.html#section-9.3:
        // [...]
        // To prove this binding, the Client Instance MUST use the client attestation mechanism when refreshing an access token.
        // The client MUST also use the same key that was present in the "cnf" claim of the client attestation that was used when the refresh token was issued.
        let wia_tokens = self
            .prepare_wallet_attestations(
                interaction_data,
                &mut [],
                organisation_id,
                &[AttestationType::WalletInstanceAttestation],
            )
            .await?;

        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let token_response: TokenResponse = async {
            let mut request =
                self.client
                    .post(token_endpoint)
                    .form(&TokenRequest::RefreshToken {
                        refresh_token: refresh_token.expose_secret().to_string(),
                    })?;

            if let Some(TokenRequestAttestationHeaders {
                wallet_attestation,
                wallet_attestation_pop,
            }) = wia_tokens
            {
                request = request
                    .header("OAuth-Client-Attestation", &wallet_attestation)
                    .header("OAuth-Client-Attestation-PoP", &wallet_attestation_pop);
            }

            request.send().await?.error_for_status()?.json()
        }
        .await
        .error_while("requesting token")?;

        self.set_token_response(interaction_data, &token_response)?;
        self.save_interaction_data(interaction_id, interaction_data)
            .await?;

        Ok(token_response.access_token)
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    async fn holder_fetch_nonce(
        &self,
        nonce_endpoint: Option<&String>,
    ) -> Result<Option<String>, IssuanceProtocolError> {
        // missing `nonce_endpoint` means the issuer does not require nonce in proofs
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.4
        let Some(nonce_endpoint) = nonce_endpoint else {
            return Ok(None);
        };

        let response: NonceResponse = async {
            self.client
                .post(nonce_endpoint.as_str())
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("requesting nonce")?;

        Ok(Some(response.c_nonce))
    }

    /// Fetches a challenge from the attestation-based client authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-11#section-6.3>
    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    async fn holder_fetch_challenge(
        &self,
        challenge_endpoint: &str,
    ) -> Result<String, IssuanceProtocolError> {
        let response: ChallengeResponse = async {
            self.client
                .post(challenge_endpoint)
                .header("Accept", "application/json")
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching challenge")?;

        Ok(response.attestation_challenge)
    }

    #[tracing::instrument(
        level = "debug",
        skip(self, message, access_token),
        err(level = "info")
    )]
    async fn send_notification(
        &self,
        message: NotificationRequest,
        notification_endpoint: &str,
        access_token: &str,
    ) -> Result<(), IssuanceProtocolError> {
        async {
            self.client
                .post(notification_endpoint)
                .bearer_auth(access_token)
                .json(&message)?
                .send()
                .await?
                .error_for_status()
        }
        .await
        .error_while("sending notification")?;

        Ok(())
    }

    async fn holder_request_credential(
        &self,
        interaction_data: &HolderInteractionData,
        requested: &RequestedCredential,
        access_token: &SecretString,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let configuration = &requested.configuration;
        let nonce = self
            .holder_fetch_nonce(interaction_data.nonce_endpoint.as_ref())
            .await?;

        let client_id = interaction_data
            .continue_issuance
            .as_ref()
            .map(|ci| &ci.client_id);

        let mut proofs = Vec::with_capacity(requested.holder_bindings.len());
        for HolderBinding {
            identifier,
            key,
            wua_proof,
        } in &requested.holder_bindings
        {
            let public_key_info = self
                .public_key_info_from_meta_and_holder_binding(configuration, identifier, key)
                .await?;

            let auth_fn = self.key_provider.get_signature_provider(
                key,
                None,
                self.key_algorithm_provider.clone(),
            )?;

            // As per https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-proof-types
            // the iss field in the proof JWT MUST be the client_id of the Client making the Credential request.
            // This claim MUST be omitted if the access token authorizing the issuance call was obtained from a Pre-Authorized Code
            let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
                interaction_data.issuer_url.to_owned(),
                public_key_info,
                nonce.to_owned(),
                wua_proof.clone(),
                auth_fn,
                client_id,
            )
            .await
            .error_while("formatting proof")?;

            proofs.push(proof_jwt);
        }

        let body = CredentialRequest {
            credential: CredentialRequestIdentifier::CredentialConfigurationId(
                configuration.credential_configuration_id.to_owned(),
            ),
            proofs: Some(Proofs::Jwt(proofs)),
            credential_response_encryption: None,
        };

        let response = self
            .fetch_credential(interaction_data, access_token, body)
            .await?;

        let credentials = response
            .standard
            .credentials
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credentials".to_string(),
            ))?
            .into_iter()
            .map(|c| c.credential.into())
            .collect();

        Ok(SubmitIssuerResponse {
            credentials,
            redirect_uri: response.redirect_uri,
            notification_id: response.standard.notification_id,
        })
    }

    async fn fetch_credential(
        &self,
        interaction_data: &HolderInteractionData,
        access_token: &SecretString,
        mut body: CredentialRequest,
    ) -> Result<OpenID4VCICredentialResponseDTO, IssuanceProtocolError> {
        let encryption_key = self.prepare_response_encryption(interaction_data, &mut body)?;
        let response: Response = if let Some(request_encryption) =
            &interaction_data.credential_request_encryption
        {
            // All algorithms defined in the enum are supported -> pick the first one
            let selected_encryption_alg = request_encryption
                .enc_values_supported
                .first()
                .cloned()
                .ok_or(IssuanceProtocolError::Failed(
                    "credential_request_encryption contains no enc_values_supported entries"
                        .to_string(),
                ))?;
            let selected_compression_alg = request_encryption.zip_values_supported.first().cloned();
            let payload = serde_json::to_vec(&body)?;
            let issuer_key = select_recipient_jwk(
                request_encryption.jwks.keys.iter().cloned(),
                &*self.key_algorithm_provider,
            )
            .ok_or(IssuanceProtocolError::Failed(
                "credential_request_encryption contains no usable key agreement key".to_string(),
            ))?;
            let encrypted = build_jwe(
                &payload,
                &issuer_key,
                JweHeader {
                    key_id: issuer_key.kid().map(String::from),
                    zip: selected_compression_alg,
                    partyuinfo_data: None,
                    partyvinfo_data: None,
                },
                selected_encryption_alg,
                &*self.key_algorithm_provider,
            )
            .await?;
            async {
                self.client
                    .post(interaction_data.credential_endpoint.as_str())
                    .bearer_auth(access_token.expose_secret())
                    .header("Content-Type", "application/jwt")
                    .body(encrypted.into_bytes())
                    .send()
                    .await?
                    .error_for_status()
            }
            .await
            .error_while("requesting credential")?
        } else {
            async {
                self.client
                    .post(interaction_data.credential_endpoint.as_str())
                    .bearer_auth(access_token.expose_secret())
                    .json(&body)?
                    .send()
                    .await?
                    .error_for_status()
            }
            .await
            .error_while("requesting credential")?
        };

        let response = if let Some(encryption_key) = encryption_key {
            let key_agreement =
                encryption_key
                    .key_agreement()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Key agreement not set".to_string(),
                    ))?;
            let content_type =
                response
                    .header_get("Content-Type")
                    .ok_or(IssuanceProtocolError::Failed(
                        "Missing response content type".to_string(),
                    ))?;
            if !is_media_type(content_type, "application/jwt") {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Requested encrypted response (application/jwt), but got `{content_type}`"
                )));
            };
            let jwe = String::from_utf8(response.body)?;
            let decrypted = decrypt_jwe_payload(
                &jwe,
                key_agreement
                    .private()
                    .ok_or(IssuanceProtocolError::Failed(
                        "private key not set".to_string(),
                    ))?
                    .as_ref(),
            )
            .await?;
            serde_json::from_slice(&decrypted)?
        } else {
            response.json().error_while("parsing credential response")?
        };

        Ok(response)
    }

    fn prepare_response_encryption(
        &self,
        interaction_data: &HolderInteractionData,
        body: &mut CredentialRequest,
    ) -> Result<Option<KeyHandle>, IssuanceProtocolError> {
        let Some(response_encryption) = &interaction_data.credential_response_encryption else {
            return Ok(None);
        };

        // ECDH-ES supports multiple curves. The metadata does not specify which curve to use.
        // P-256 is used as it is the most likely supported curve.
        let Some(algorithm) = self
            .key_algorithm_provider
            .key_algorithm_from_type(KeyAlgorithmType::Ecdsa)
            .ok()
        else {
            // If this becomes an issue, fallback to other curves could be implemented.
            return if response_encryption.encryption_required {
                Err(IssuanceProtocolError::Failed(
                    "Response encryption is required, but ECDSA key algorithm is not available"
                        .to_string(),
                ))
            } else {
                // Encryption is not required, so it is skipped
                tracing::warn!(
                    "Skipping optional response encryption because ECDSA key algorithm is not available"
                );
                Ok(None)
            };
        };
        let enc = response_encryption
            .enc_values_supported
            .first()
            .cloned()
            .ok_or(IssuanceProtocolError::Failed(
                "credential_response_encryption contains no enc_values_supported entries"
                    .to_string(),
            ))?;

        let response_encryption_key = algorithm
            .generate_key()
            .error_while("Generating encryption key")?;
        let key_agreement =
            response_encryption_key
                .key
                .key_agreement()
                .ok_or(IssuanceProtocolError::Failed(
                    "Key agreement not set".to_string(),
                ))?;
        // A freshly generated key does not have a use attached to it, so jwk created with explicit use
        let jwk =
            ecdsa_public_key_as_jwk(&key_agreement.public().as_raw(), Some(JwkUse::Encryption))
                .error_while("Generating JWK")?;
        body.credential_response_encryption = Some(ResponseEncryption {
            jwk,
            enc,
            zip: response_encryption.zip_values_supported.first().cloned(),
        });
        Ok(Some(response_encryption_key.key))
    }

    async fn public_key_info_from_meta_and_holder_binding(
        &self,
        configuration: &HolderCredentialConfiguration,
        identifier: &Identifier,
        key: &Key,
    ) -> Result<PublicKeyInfo, IssuanceProtocolError> {
        // Should be optional, but currently not supported by core.
        //
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.11.2.4:
        // It MUST be present when Cryptographic Key Binding is required for a Credential, and omitted otherwise.
        // If absent, Cryptographic Key Binding is not required for this credential.
        let Some(methods) = &configuration.cryptographic_binding_methods_supported else {
            return Err(IssuanceProtocolError::Failed("No cryptographic_binding_methods_supported available in metadata. Credentials without holder binding are not supported.".to_string()));
        };
        let info = match &identifier.data {
            IdentifierData::Did(did) => {
                let did = did.as_ref().await?;
                if methods
                    .iter()
                    .any(|method| &format!("did:{}", did.did.method()) == method)
                {
                    let related_key = did
                        .find_key(&key.id, &KeyFilter::did_role(KeyRole::Authentication))
                        .await
                        .error_while("finding related key")?;

                    PublicKeyInfo::KeyId(did.verification_method_id(&related_key))
                } else {
                    self.jwk_proof_info_from_key(identifier, key, methods)?
                }
            }
            IdentifierData::Key(_) => self.jwk_proof_info_from_key(identifier, key, methods)?,
            r#type => {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Unsupported identifier type: {}",
                    r#type.r#type()
                )));
            }
        };
        Ok(info)
    }

    fn jwk_proof_info_from_key(
        &self,
        identifier: &Identifier,
        key: &Key,
        methods: &Vec<String>,
    ) -> Result<PublicKeyInfo, IssuanceProtocolError> {
        if !methods.contains(&"jwk".to_string()) && !methods.contains(&"cose_key".to_string()) {
            return Err(IssuanceProtocolError::Failed(format!(
                "No matching cryptographic binding method found for identifier {} and key {}. Options supported by the issue: `{methods:?}`",
                identifier.id, key.id
            )));
        }
        let jwk = self
            .key_algorithm_provider
            .reconstruct_key(
                key.key_algorithm_type()
                    .error_while("getting key algorithm type")?,
                &key.public_key,
                None,
                None,
            )
            .error_while("reconstructing key")?
            .public_key_as_jwk()
            .error_while("getting JWK")?;
        Ok(PublicKeyInfo::Jwk(jwk))
    }

    async fn upsert_credential_blob(
        &self,
        credential: &Credential,
        token: &SerializedCredential,
    ) -> Result<BlobId, IssuanceProtocolError> {
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let credential_blob_id = match credential.credential_blob_id {
            None => {
                let blob = Blob::new(token.as_ref(), BlobType::Credential);
                db_blob_storage
                    .create(blob.clone())
                    .await
                    .error_while("creating blob")?;
                blob.id
            }
            Some(blob_id) => {
                db_blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(token.as_ref().into()),
                        },
                    )
                    .await
                    .error_while("updating blob")?;
                blob_id
            }
        };
        Ok(credential_blob_id)
    }

    async fn prepare_requested_credentials(
        &self,
        interaction_data: &HolderInteractionData,
        configurations: Vec<HolderCredentialConfiguration>,
        holder_binding: Option<&HolderBindingInput>,
        organisation: &Organisation,
        autogenerated_bindings: &mut Vec<HolderBinding>,
    ) -> Result<Vec<RequestedCredential>, IssuanceProtocolError> {
        let mut requested_credentials = Vec::with_capacity(configurations.len());
        for configuration in configurations {
            let holder_bindings = match holder_binding {
                Some(holder_binding) => vec![holder_binding.to_owned().into()],
                None => {
                    let holder_bindings = self
                        .create_holder_binding(interaction_data, &configuration, organisation)
                        .await?;
                    // deleted again unless a credential uses them
                    autogenerated_bindings.extend(holder_bindings.iter().cloned());
                    holder_bindings
                }
            };
            requested_credentials.push(RequestedCredential {
                configuration,
                holder_bindings,
            });
        }
        Ok(requested_credentials)
    }

    async fn holder_accept_configuration(
        &self,
        interaction_data: &mut HolderInteractionData,
        requested: RequestedCredential,
        access_token: &SecretString,
        interaction: &Interaction,
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;
        let credential_response = self
            .holder_request_credential(interaction_data, &requested, access_token)
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        let RequestedCredential {
            configuration,
            holder_bindings,
        } = requested;
        let result = self
            .holder_process_accepted_credentials(
                credential_response,
                interaction_data,
                &configuration,
                holder_bindings,
                &organisation,
                interaction,
            )
            .await;

        if let Some(stored) =
            interaction_data.configuration_mut(&configuration.credential_configuration_id)
        {
            stored.credential_metadata = None;
            stored.notification_id = notification_id.clone();
            stored.credential_id = result
                .as_ref()
                .ok()
                .map(|response| response.main_credential.credential.id);
            stored.credential_schema_format_id = result.as_ref().ok().and_then(|response| {
                response
                    .batch_items
                    .first()
                    .unwrap_or(&response.main_credential)
                    .credential
                    .format
                    .as_ref()
                    .map(Related::id)
            });
        }

        if let (Some(notification_id), Some(notification_endpoint)) =
            (notification_id, &interaction_data.notification_endpoint)
        {
            let notification = match &result {
                Ok(_) => NotificationRequest {
                    notification_id,
                    event: NotificationEvent::CredentialAccepted,
                    event_description: None,
                },
                Err(err) => NotificationRequest::failure(notification_id, &err.to_string()),
            };

            if let Err(error) = self
                .send_notification(
                    notification,
                    notification_endpoint.as_str(),
                    access_token.expose_secret(),
                )
                .await
            {
                tracing::warn!(%error, "Notification failure");
            }
        }

        result
    }

    /// Selects accepted configurations whose batch parents can still be refreshed, or the
    /// exact configuration of an MSO item. Missing associations are resolved for legacy data.
    async fn select_refresh_configurations(
        &self,
        interaction: &Interaction,
        data: &HolderInteractionData,
        updated: Option<&Credential>,
    ) -> Result<Vec<RefreshConfiguration>, IssuanceProtocolError> {
        if let Some(credential) = updated {
            if credential.state == CredentialStateEnum::Rejected {
                return Err(IssuanceProtocolError::RefreshNotPossible);
            }
            let main_id = credential
                .parent
                .as_ref()
                .map_or(credential.id, Related::id);
            let format_id = credential.format.as_required_ref().await?.id;
            let mut configuration = data
                .configurations_for_credential(main_id)
                .filter(|configuration| {
                    configuration
                        .credential_schema_format_id
                        .is_none_or(|id| id == format_id)
                })
                .exactly_one()
                .map_err(|_| {
                    IssuanceProtocolError::Failed(
                        "Missing or ambiguous credential configuration for MSO refresh".to_string(),
                    )
                })?
                .clone();
            configuration.credential_id = Some(main_id);
            configuration.credential_schema_format_id = Some(format_id);
            return Ok(vec![RefreshConfiguration {
                configuration,
                holder_binding: Some(Self::credential_holder_binding(credential).await?),
            }]);
        }

        let credentials = self
            .credential_repository
            .get_credentials_by_interaction_id(&interaction.id)
            .await
            .error_while("getting accepted credentials")?;
        let mut configurations = vec![];
        let mut unsupported_fixed_binding = false;
        for configuration in &data.credential_configurations {
            let Some(parent) = credentials.iter().find(|credential| {
                credential.r#type == CredentialType::BatchParent
                    && credential.deleted_at.is_none()
                    && credential.state != CredentialStateEnum::Rejected
                    && configuration
                        .credential_id
                        .map_or(data.credential_configurations.len() == 1, |id| {
                            id == credential.id
                        })
            }) else {
                // Failed/skipped configurations have no stored credential. A legacy association
                // without an ID is usable only when its parent actually exists.
                continue;
            };
            if self
                .batch_format_is_rejected(parent.id, configuration.credential_schema_format_id)
                .await?
            {
                continue;
            }
            let mut configuration = configuration.clone();
            configuration.credential_id = Some(parent.id);
            // Binding and expiry belong to concrete items, not their format-agnostic parent.
            // Include consumed and expired items: they still determine how to renew the batch.
            let items = self
                .credential_repository
                .get_credential_list(ListQuery {
                    include_count: false,
                    pagination: Some(ListPagination {
                        page: 0,
                        page_size: 1,
                    }),
                    filtering: Some(
                        CredentialFilterValue::ParentCredential(parent.id).condition()
                            & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                            & CredentialFilterValue::Deleted(false)
                            & configuration
                                .credential_schema_format_id
                                .map(|id| CredentialFilterValue::FormatIds(vec![id])),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting batch item for refresh")?;
            let Some(item) = items.values.first() else {
                continue;
            };
            let fixed_binding = match &item.holder_identifier {
                Some(identifier) => !identifier.as_ref().await?.autogenerated,
                None => false,
            };
            if fixed_binding && item.expires_at.is_none() {
                unsupported_fixed_binding = true;
                continue;
            }
            configuration.credential_schema_format_id = item.format.as_ref().map(Related::id);
            configurations.push(RefreshConfiguration {
                configuration,
                holder_binding: if fixed_binding {
                    Some(Self::credential_holder_binding(item).await?)
                } else {
                    None
                },
            });
        }
        if configurations.is_empty() && unsupported_fixed_binding {
            return Err(IssuanceProtocolError::RefreshNotSupported(
                CredentialType::BatchParent,
            ));
        }
        Ok(configurations)
    }

    async fn credential_holder_binding(
        credential: &Credential,
    ) -> Result<HolderBindingInput, IssuanceProtocolError> {
        let identifier = credential
            .holder_identifier
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing holder_identifier".to_string(),
            ))?
            .as_ref()
            .await?
            .to_owned();
        let key = credential
            .key
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing key".to_string()))?
            .as_ref()
            .await?
            .to_owned();
        Ok(HolderBindingInput { identifier, key })
    }

    /// Rejection is scoped to the parent and exact schema format. Include old, consumed and
    /// deleted items: their stored rejection state still determines whether the format can
    /// be refreshed. Legacy single-format interactions have no stored format ID.
    async fn batch_format_is_rejected(
        &self,
        parent_id: CredentialId,
        format_id: Option<CredentialSchemaFormatId>,
    ) -> Result<bool, IssuanceProtocolError> {
        let items = self
            .credential_repository
            .get_credential_list(ListQuery {
                include_count: false,
                filtering: Some(
                    CredentialFilterValue::ParentCredential(parent_id).condition()
                        & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                        & format_id.map(|id| CredentialFilterValue::FormatIds(vec![id])),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting batch items for rejection")?
            .values;
        Ok(!items.is_empty()
            && items
                .iter()
                .all(|item| item.state == CredentialStateEnum::Rejected))
    }

    async fn get_batch_schema_format(
        &self,
        parent: &Credential,
        configuration: &HolderCredentialConfiguration,
        format_type: FormatType,
    ) -> Result<CredentialSchemaFormat, IssuanceProtocolError> {
        let format = if let Some(format_id) = configuration.credential_schema_format_id {
            parent
                .schema
                .as_ref()
                .await?
                .formats
                .as_ref()
                .await?
                .iter()
                .find(|format| format.id == format_id)
                .cloned()
                .ok_or_else(|| {
                    IssuanceProtocolError::Failed(format!(
                        "Credential schema format {format_id} missing from batch schema"
                    ))
                })?
        } else {
            // Legacy batches predate the exact association. Resolve it from concrete items;
            // schema order and a parent's legacy format do not identify the issued format.
            let items = self
                .credential_repository
                .get_credential_list(ListQuery {
                    filtering: Some(
                        CredentialFilterValue::ParentCredential(parent.id).condition()
                            & CredentialFilterValue::Types(vec![CredentialType::BatchItem])
                            & CredentialFilterValue::Deleted(false),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("getting legacy batch items")?;
            let mut formats = vec![];
            for item in items.values {
                let format = item.format.as_required_ref().await?;
                if self
                    .config
                    .format
                    .get_type(&format.format)
                    .error_while("getting format type")?
                    == format_type
                {
                    formats.push(format.to_owned());
                }
            }
            formats
                .into_iter()
                .unique_by(|format| format.id)
                .exactly_one()
                .map_err(|_| {
                    IssuanceProtocolError::Failed(
                        "Missing or ambiguous format association for legacy batch".to_string(),
                    )
                })?
        };
        if self
            .config
            .format
            .get_type(&format.format)
            .error_while("getting format type")?
            != format_type
        {
            return Err(IssuanceProtocolError::Failed(
                "Refreshed credential format changed".to_string(),
            ));
        }
        Ok(format)
    }

    async fn holder_refresh_configuration(
        &self,
        interaction: &Interaction,
        interaction_data: &mut HolderInteractionData,
        requested: RequestedCredential,
        updated_credential: Option<&Credential>,
        access_token: &SecretString,
    ) -> Result<Vec<Credential>, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;
        let response = self
            .holder_request_credential(interaction_data, &requested, access_token)
            .await?;
        let RequestedCredential {
            configuration,
            holder_bindings,
        } = requested;

        let notification_id = response.notification_id.to_owned();
        let refreshed = self
            .holder_process_refresh(
                &configuration,
                holder_bindings,
                response,
                &organisation,
                updated_credential.cloned(),
                interaction,
            )
            .await;

        let mut interaction_data_changed = false;
        if let Some(stored) =
            interaction_data.configuration_mut(&configuration.credential_configuration_id)
        {
            // Current issuers can rotate notification IDs on every refresh.
            if notification_id.is_some() && stored.notification_id != notification_id {
                stored.notification_id = notification_id.clone();
                interaction_data_changed = true;
            }
            // A successful legacy refresh resolves associations absent from the old interaction.
            if let Ok(credentials) = &refreshed
                && let Some(credential) = credentials.first()
            {
                if stored.credential_id.is_none() {
                    stored.credential_id = Some(
                        credential
                            .parent
                            .as_ref()
                            .map_or(credential.id, Related::id),
                    );
                    interaction_data_changed = true;
                }
                if stored.credential_schema_format_id.is_none()
                    && let Some(format) = &credential.format
                {
                    stored.credential_schema_format_id = Some(format.id());
                    interaction_data_changed = true;
                }
            }
        }
        if interaction_data_changed {
            self.save_interaction_data(interaction.id, interaction_data)
                .await?;
        }

        if let (Err(err), Some(notification_id), Some(notification_endpoint)) = (
            &refreshed,
            notification_id,
            &interaction_data.notification_endpoint,
        ) {
            let notification = NotificationRequest::failure(notification_id, &err.to_string());

            if let Err(error) = self
                .send_notification(
                    notification,
                    notification_endpoint.as_str(),
                    access_token.expose_secret(),
                )
                .await
            {
                tracing::warn!(%error, "Notification failure");
            }
        }

        refreshed
    }

    /// Prepares and attests the holder bindings, requests the token and accepts each configuration
    async fn holder_accept_offer(
        &self,
        interaction: &Interaction,
        interaction_data: &mut HolderInteractionData,
        configurations: Vec<HolderCredentialConfiguration>,
        holder_binding: Option<&HolderBindingInput>,
        tx_code: Option<String>,
        autogenerated_bindings: &mut Vec<HolderBinding>,
    ) -> Result<IssuanceAcceptResult, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;
        let mut requested_credentials = self
            .prepare_requested_credentials(
                interaction_data,
                configurations,
                holder_binding,
                &organisation,
                autogenerated_bindings,
            )
            .await?;
        // the token is requested once, attested together with the keys of every configuration
        let wia_tokens = self
            .prepare_wallet_attestations(
                interaction_data,
                &mut requested_credentials,
                organisation.id,
                &[
                    AttestationType::WalletInstanceAttestation,
                    AttestationType::KeyAttestation,
                ],
            )
            .await?;
        let token_response = self
            .holder_fetch_token(interaction_data, tx_code, wia_tokens)
            .await?;
        // a failed accept attempt may have stored a refresh token, this response replaces it
        interaction_data.refresh_token = None;
        interaction_data.refresh_token_expires_at = None;
        self.set_token_response(interaction_data, &token_response)?;

        let mut result = IssuanceAcceptResult::default();
        for requested in requested_credentials {
            let credential_configuration_id = requested
                .configuration
                .credential_configuration_id
                .to_owned();
            let accepted = self
                .holder_accept_configuration(
                    interaction_data,
                    requested,
                    &token_response.access_token,
                    interaction,
                )
                .await;
            result.record(&credential_configuration_id, accepted);
        }

        let has_multiple_configurations = interaction_data.credential_configurations.len() > 1;
        let has_refresh_token = interaction_data.refresh_token.is_some();
        let advertised_batch_size = interaction_data.batch_size;
        let any_batch_issued = result
            .issued
            .iter()
            .any(|response| !response.batch_items.is_empty());
        for response in &mut result.issued {
            if should_create_batch_parent(
                response,
                has_multiple_configurations,
                has_refresh_token,
                advertised_batch_size,
                any_batch_issued,
            ) {
                let parent = response.main_credential.batch_parent(has_refresh_token);
                let mut item = std::mem::replace(&mut response.main_credential, parent);
                let parent_id = response.main_credential.credential.id;
                self.change_to_batch_item(&mut item.credential, parent_id);
                for batch_item in &mut response.batch_items {
                    self.change_to_batch_item(&mut batch_item.credential, parent_id);
                }
                response.batch_items.insert(0, item);
                if let Some(configuration) =
                    interaction_data.configuration_mut(&response.credential_configuration_id)
                {
                    configuration.credential_id = Some(parent_id);
                }
            }
        }
        Ok(result)
    }

    /// Stores the encrypted tokens of the response in the interaction data
    fn set_token_response(
        &self,
        interaction_data: &mut HolderInteractionData,
        token_response: &TokenResponse,
    ) -> Result<(), IssuanceProtocolError> {
        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        // no refresh token in the response means the issuer did not rotate it, the stored one stays
        if let Some(refresh_token) = &token_response.refresh_token {
            let encrypted_refresh_token = encrypt_string(refresh_token, &self.params.encryption)
                .map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token = Some(encrypted_refresh_token);
            interaction_data.refresh_token_expires_at = token_response
                .refresh_token_expires_in
                .as_ref()
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }
        Ok(())
    }

    async fn save_interaction_data(
        &self,
        interaction_id: InteractionId,
        interaction_data: &HolderInteractionData,
    ) -> Result<(), IssuanceProtocolError> {
        self.interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(interaction_data)?)),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;
        Ok(())
    }

    /// Removes the identifier, DID and key of each auto-generated binding that no credential uses
    async fn delete_unused_autogenerated_bindings(
        &self,
        autogenerated_bindings: &[HolderBinding],
        used_identifier_ids: HashSet<IdentifierId>,
    ) -> Result<(), IssuanceProtocolError> {
        for binding in autogenerated_bindings
            .iter()
            .filter(|binding| !used_identifier_ids.contains(&binding.identifier.id))
        {
            self.tx_manager
                .tx(async {
                    self.identifier_repository
                        .hard_delete(&binding.identifier.id)
                        .await
                        .error_while("hard deleting unused auto-generated identifier")?;
                    if let IdentifierData::Did(did) = &binding.identifier.data {
                        self.did_repository
                            .hard_delete(&did.id())
                            .await
                            .error_while("hard deleting unused auto-generated did")?;
                    }
                    self.key_repository
                        .hard_delete(&binding.key.id)
                        .await
                        .error_while("hard deleting unused auto-generated key")?;
                    Ok::<_, IssuanceProtocolError>(())
                })
                .await
                .error_while("deleting unused auto-generated binding")??;
        }
        Ok(())
    }

    async fn create_holder_binding(
        &self,
        interaction_data: &HolderInteractionData,
        configuration: &HolderCredentialConfiguration,
        organisation: &Organisation,
    ) -> Result<Vec<HolderBinding>, IssuanceProtocolError> {
        let generate_binding = async || {
            autogenerate_holder_binding(
                configuration
                    .cryptographic_binding_methods_supported
                    .as_ref(),
                configuration.proof_types_supported.as_ref(),
                organisation,
                self.key_provider.as_ref(),
                self.key_algorithm_provider.as_ref(),
                self.key_security_level_provider.as_ref(),
                self.did_method_provider.as_ref(),
                self.key_repository.as_ref(),
                self.identifier_creator.as_ref(),
            )
            .await
        };

        Ok(if let Some(batch_size) = interaction_data.batch_size {
            let mut result = Vec::with_capacity(batch_size as _);
            for _ in 0..batch_size {
                result.push(generate_binding().await?.into());
            }
            result
        } else {
            vec![generate_binding().await?.into()]
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    async fn fetch_issuer_metadata(
        &self,
        credential_issuer: &str,
        organisation: &Organisation,
    ) -> Result<IssuerMetadataRepresentation, IssuanceProtocolError> {
        let credential_issuer_endpoint: Url = credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::InvalidRequest(format!(
                "Invalid credential issuer url {credential_issuer}",
            ))
        })?;

        let trust_mandatory = organisation.configuration.enforce_ecosystem_as_holder;

        let jwt_result = fetch_metadata_jwt_with_fallback(
            self.metadata_cache.as_ref(),
            &credential_issuer_endpoint,
            "openid-credential-issuer",
        )
        .await;

        if !trust_mandatory && let Err(err) = &jwt_result {
            tracing::warn!(
                "Failed to fetch signed issuer metadata, falling back to unsigned metadata: {err}"
            );
            return Ok(IssuerMetadataRepresentation::Unsigned(
                fetch_metadata_json_with_fallback(
                    self.metadata_cache.as_ref(),
                    &credential_issuer_endpoint,
                    "openid-credential-issuer",
                )
                .await?,
            ));
        }

        let jwt = jwt_result?;
        self.validate_jwt(&jwt)
            .await
            .error_while("validating issuer metadata JWT")?;

        Ok(IssuerMetadataRepresentation::Signed(jwt))
    }

    async fn validate_jwt<T: Debug>(
        &self,
        jwt: &DecomposedJwt<T>,
    ) -> Result<(), IssuanceProtocolError> {
        let public_key_source = jwt
            .public_key_source(None)
            .error_while("extracting public key info from JWT")?;
        jwt.verify_signature(public_key_source, &self.verification_fn())
            .await
            .error_while("verifying JWT signature")?;

        Ok(())
    }

    fn verification_fn(&self) -> VerificationFn {
        Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        })
    }

    #[expect(clippy::too_many_arguments)]
    async fn prepare_issuance_interaction(
        &self,
        organisation: Organisation,
        token_endpoint: String,
        issuer_metadata: &IssuerMetadataRepresentation,
        oauth_authorization_server_metadata: Option<AuthorizationServerMetadata>,
        grants: Grants,
        configuration_ids: &[String],
        continue_issuance: Option<ContinueIssuanceDTO>,
    ) -> Result<PrepareIssuanceSuccess, IssuanceProtocolError> {
        if configuration_ids.is_empty() {
            return Err(IssuanceProtocolError::Failed(
                "Credential offer is missing credentials".to_string(),
            ));
        }

        let mut credential_configurations = Vec::with_capacity(configuration_ids.len());
        // the holder binding key must satisfy every offered configuration
        let mut key_algorithms = None;
        let mut key_storage_security = None;
        for configuration_id in configuration_ids {
            let credential_config = issuer_metadata
                .metadata()
                .credential_configurations_supported
                .get(configuration_id)
                .ok_or_else(|| {
                    IssuanceProtocolError::Failed(format!(
                        "Credential configuration is missing for {configuration_id}"
                    ))
                })?;

            validator::validate_key_requirements_supported(
                self.key_algorithm_provider.as_ref(),
                self.key_provider.as_ref(),
                self.key_security_level_provider.as_ref(),
                credential_config,
            )?;

            let (algorithms, storage_security) =
                credential_config_to_holder_signing_algs_and_key_storage_security(
                    self.key_algorithm_provider.as_ref(),
                    credential_config,
                );
            key_algorithms = intersect_supported(key_algorithms, algorithms);
            key_storage_security = intersect_supported(key_storage_security, storage_security);

            credential_configurations.push(HolderCredentialConfiguration {
                credential_configuration_id: configuration_id.to_owned(),
                format: credential_config.format.to_owned(),
                cryptographic_binding_methods_supported: credential_config
                    .cryptographic_binding_methods_supported
                    .clone(),
                credential_signing_alg_values_supported: credential_config
                    .credential_signing_alg_values_supported
                    .clone(),
                proof_types_supported: credential_config.proof_types_supported.clone(),
                credential_metadata: credential_config.credential_metadata.clone(),
                disclosure_policy: credential_config.disclosure_policy.clone(),
                notification_id: None,
                credential_id: None,
                credential_schema_format_id: None,
            });
        }

        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        if let Some(authorization_server) = grants.authorization_server()
            && issuer_metadata
                .metadata()
                .authorization_servers
                .as_ref()
                .is_none_or(|servers| !servers.contains(authorization_server))
        {
            return Err(IssuanceProtocolError::InvalidRequest(format!(
                "Authorization server missing in issuer metadata: {authorization_server}"
            )));
        }

        let token_endpoint_auth_methods_supported = oauth_authorization_server_metadata
            .as_ref()
            .map(|oauth_metadata| oauth_metadata.token_endpoint_auth_methods_supported.clone());
        let client_attestation_pop_signing_alg_values_supported =
            oauth_authorization_server_metadata
                .as_ref()
                .and_then(|oauth_metadata| {
                    oauth_metadata
                        .client_attestation_pop_signing_alg_values_supported
                        .clone()
                });

        let challenge_endpoint = oauth_authorization_server_metadata
            .as_ref()
            .and_then(|oauth_metadata| oauth_metadata.challenge_endpoint.as_ref())
            .map(Url::to_string);

        let holder_data = HolderInteractionData {
            issuer_url: issuer_metadata.metadata().credential_issuer.clone(),
            credential_endpoint: issuer_metadata.metadata().credential_endpoint.clone(),
            notification_endpoint: issuer_metadata.metadata().notification_endpoint.to_owned(),
            nonce_endpoint: issuer_metadata.metadata().nonce_endpoint.to_owned(),
            batch_size: issuer_metadata
                .metadata()
                .batch_credential_issuance
                .as_ref()
                .map(|data| data.batch_size),
            challenge_endpoint,
            token_endpoint: Some(token_endpoint),
            grants: Some(grants),
            continue_issuance,
            access_token: None,
            access_token_expires_at: None,
            refresh_token: None,
            refresh_token_expires_at: None,
            token_endpoint_auth_methods_supported,
            client_attestation_pop_signing_alg_values_supported,
            issuer_display: issuer_metadata.metadata().display.clone(),
            credential_request_encryption: issuer_metadata
                .metadata()
                .credential_request_encryption
                .clone(),
            credential_response_encryption: issuer_metadata
                .metadata()
                .credential_response_encryption
                .clone(),
            protocol: self.config_id.to_owned(),
            credential_configurations,
        };
        let data = serialize_interaction_data(&holder_data)?;

        let interaction =
            create_and_store_interaction(self.interaction_repository.as_ref(), data, organisation)
                .await?;
        Ok(PrepareIssuanceSuccess {
            interaction_id: interaction.id,
            key_storage_security,
            key_algorithms,
        })
    }

    pub(super) async fn get_etsi_issuer_info(
        &self,
        identifier: &Identifier,
        credential_schema: &CredentialSchema,
    ) -> Result<Vec<IssuerInfoAttestation>, IssuanceProtocolError> {
        let trust_information_list = identifier.trust_information.as_ref().await?;
        if trust_information_list.is_empty() {
            return Ok(vec![]);
        }

        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;

        let formats = credential_schema.formats.as_ref().await?;

        let mut result = Vec::new();
        for format in &formats {
            let format_type = self
                .config
                .format
                .get_fields(&format.format)
                .error_while("getting format config")?
                .r#type;

            let valid_trust_information_list = trust_information_list
                .iter()
                .filter(|ti| ti.is_valid(now_utc()))
                .filter(|ti| ti.is_issuance_allowed_for(&format.ecosystem_schema_id, &format_type));

            for trust_information in valid_trust_information_list {
                let certificate = blob_storage
                    .get(&trust_information.blob_id)
                    .await
                    .error_while("getting trust information blob")?
                    .ok_or(IssuanceProtocolError::TrustInformationError(
                        "Missing registration certificate".to_string(),
                    ))?;

                if certificate.r#type != BlobType::RegistrationCertificate {
                    return Err(IssuanceProtocolError::TrustInformationError(format!(
                        "Invalid trust information data, expected registration certificate, got {:?}",
                        certificate.r#type
                    )));
                }

                result.push(IssuerInfoAttestation {
                    format: IssuerInfoAttestationFormat::RegistrationCert,
                    data: String::from_utf8(certificate.value)?,
                    credential_ids: trust_information
                        .allowed_issuance_types
                        .iter()
                        .map(|ti| CredentialQueryId::from(ti.schema_id.as_str()))
                        .collect(),
                })
            }
        }

        Ok(result)
    }

    pub(super) async fn prepare_issuer_metadata(
        &self,
        credential_schema_id: &CredentialSchemaId,
    ) -> Result<PreparedMetadata, IssuanceProtocolError> {
        let protocol_base_url =
            self.protocol_base_url
                .clone()
                .ok_or(IssuanceProtocolError::Failed(
                    "Host URL not specified".to_string(),
                ))?;

        let schema = self
            .credential_schema_repository
            .get_credential_schema(credential_schema_id)
            .await
            .error_while("getting credential schema")?;

        let mut credential_configurations_supported: IndexMap<String, CredentialConfiguration> =
            Default::default();
        {
            let proof_types_supported: IndexMap<String, ProofTypeSupported> =
                map_proof_types_supported(
                    self.key_algorithm_provider
                        .supported_verification_jose_alg_ids(),
                    &schema.wallet_attestation,
                );

            let formats = schema.formats.as_ref().await?;
            for format in &formats {
                let format_type = self
                    .config
                    .format
                    .get_fields(&format.format)
                    .error_while("getting format config")?
                    .r#type;

                let formatter = self
                    .formatter_provider
                    .get_credential_formatter(&format.format)?;

                let format_capabilities = formatter.get_capabilities();
                let credential_signing_alg_values_supported = format_capabilities
                    .signing_key_algorithms
                    .into_iter()
                    .filter_map(|alg_type| {
                        self.key_algorithm_provider
                            .key_algorithm_from_type(alg_type)
                            .ok()
                            .map(|alg| alg.issuance_jose_alg_id())
                    })
                    .collect();

                let configuration = credential_configuration_supported(
                    &format_type,
                    format,
                    &schema,
                    &self.config.datatype,
                    map_cryptographic_binding_methods_supported(
                        &self.did_method_provider.supported_method_names(),
                        &format_capabilities.holder_identifier_types,
                    ),
                    proof_types_supported.to_owned(),
                    credential_signing_alg_values_supported,
                )
                .await
                .map_err(OpenIDIssuanceError::OpenID4VCI)?;

                credential_configurations_supported
                    .insert(format.ecosystem_schema_id.to_owned(), configuration);
            }
        }

        Ok(PreparedMetadata {
            protocol_base_url,
            schema,
            credential_configurations_supported,
        })
    }

    /// Credential Request encryption to advertise, or `None` when we cannot decrypt.
    ///
    /// Requires a static key of the issuer that can perform ECDH, so this is only advertised when
    /// the issuer identifier actually owns such a key.
    pub(super) async fn credential_request_encryption(
        &self,
        issuer_identifier: &Identifier,
        enc_values_supported: Vec<EncryptionAlgorithm>,
    ) -> Result<Option<CredentialRequestEncryption>, IssuanceProtocolError> {
        let keys = self.issuer_key_agreement_keys(issuer_identifier).await?;
        if keys.is_empty() {
            if self.params.credential_endpoint_encryption.request_required {
                tracing::warn!(
                    "Credential request encryption is required, but issuer identifier {} has no key supporting key agreement",
                    issuer_identifier.id
                );
            }
            return Ok(None);
        }

        Ok(Some(CredentialRequestEncryption {
            jwks: Jwks {
                keys: keys.into_iter().map(|key| key.jwk).collect(),
            },
            enc_values_supported,
            zip_values_supported: vec![CompressionAlgorithm::DEF],
            encryption_required: self.params.credential_endpoint_encryption.request_required,
        }))
    }

    /// Credential Response encryption to advertise, or `None` when we cannot encrypt.
    ///
    /// The key agreement uses an ephemeral key generated for the wallet's key algorithm, so this
    /// only depends on a key-agreement capable key algorithm being configured.
    pub(super) fn credential_response_encryption(
        &self,
        enc_values_supported: Vec<EncryptionAlgorithm>,
    ) -> Option<CredentialResponseEncryption> {
        let supported = self
            .key_algorithm_provider
            .algorithms()
            .iter()
            .any(|(_, alg)| {
                alg.enabled()
                    && alg
                        .get_capabilities()
                        .features
                        .contains(&KeyAlgorithmFeatures::KeyAgreement)
            });
        if !supported {
            return None;
        }

        Some(CredentialResponseEncryption {
            alg_values_supported: vec![EncryptionKeyManagementAlgorithm::EcdhEs],
            enc_values_supported,
            zip_values_supported: vec![CompressionAlgorithm::DEF],
            encryption_required: self.params.credential_endpoint_encryption.response_required,
        })
    }

    /// Keys of the issuer identifier usable as the static side of an ECDH-ES key agreement.
    pub(super) async fn issuer_key_agreement_keys(
        &self,
        issuer_identifier: &Identifier,
    ) -> Result<Vec<KeyAgreementKey>, IssuanceProtocolError> {
        Ok(key_agreement_keys(
            issuer_identifier,
            None,
            self.params.swiyu_mode,
            &*self.key_provider,
            &*self.key_algorithm_provider,
        )
        .await?)
    }
}

#[async_trait]
impl IssuanceProtocol for OpenID4VCIFinal1_0 {
    fn holder_can_handle(&self, url: &Url) -> bool {
        if self.params.url_scheme != url.scheme() {
            return false;
        }

        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);
        if !query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
            && !query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY)
        {
            return false;
        }

        true
    }

    async fn holder_handle_invitation<'a>(
        &self,
        url: Url,
        organisation: Organisation,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum<'a>, IssuanceProtocolError> {
        let credential_offer = resolve_credential_offer(self.client.as_ref(), url).await?;

        let issuer_metadata = self
            .fetch_issuer_metadata(&credential_offer.credential_issuer, &organisation)
            .await?;

        let AuthorizationMetadata {
            token_endpoint,
            oauth_metadata,
            ..
        } = get_authorization_metadata(
            self.metadata_cache.as_ref(),
            issuer_metadata.metadata(),
            &credential_offer.credential_issuer,
            credential_offer.grants.authorization_server(),
        )
        .await?;

        if let Grants::AuthorizationCode(authorization_code) = credential_offer.grants {
            let params = self
                .config
                .credential_issuer
                .entities
                .iter()
                .filter(|(_, entity)| entity.enabled.unwrap_or(true))
                .filter_map(|(key, entity)| {
                    parse_credential_issuer_params(key, &entity.params).ok()
                })
                .find(|params| params.issuer == credential_offer.credential_issuer)
                .ok_or(IssuanceProtocolError::InvalidRequest(format!(
                    "No config entry for Authorization Code found, issuer: {}",
                    credential_offer.credential_issuer
                )))?;

            let credential_configuration_ids = credential_offer.credential_configuration_ids;
            if credential_configuration_ids.is_empty() {
                return Err(IssuanceProtocolError::InvalidRequest(
                    "No credential_configuration_ids provided".to_string(),
                ));
            }

            let scope = credential_configuration_ids
                .iter()
                .map(|id| {
                    issuer_metadata
                        .metadata()
                        .credential_configurations_supported
                        .get(id)
                        .and_then(|c| c.scope.clone())
                })
                .collect::<Option<Vec<String>>>();

            return Ok(InvitationResponseEnum::AuthorizationFlow {
                organisation_id: organisation.id,
                issuer: params.issuer,
                scope,
                client_id: params.client_id,
                redirect_uri,
                authorization_details: Some(
                    credential_configuration_ids
                        .iter()
                        .map(|configuration_id| AuthorizationDetail {
                            r#type: "openid_credential".to_string(),
                            credential_configuration_id: configuration_id.to_owned(),
                        })
                        .collect(),
                ),
                issuer_state: authorization_code.issuer_state,
                authorization_server: authorization_code.authorization_server,
                ecosystem_artifact: ProtocolArtifact::HolderIssuanceInvitation {
                    issuer_metadata: issuer_metadata.into(),
                    credential_configuration_ids,
                },
            });
        }

        let tx_code = credential_offer.grants.tx_code().cloned();
        let requires_wallet_instance_attestation =
            requires_wia(&oauth_metadata.token_endpoint_auth_methods_supported);

        if requires_wallet_instance_attestation {
            validator::validate_has_active_wallet_instance(
                self.holder_wallet_unit_repository.as_ref(),
                organisation.id,
            )
            .await?;
        }

        let PrepareIssuanceSuccess {
            interaction_id,
            key_storage_security,
            key_algorithms,
        } = self
            .prepare_issuance_interaction(
                organisation,
                token_endpoint,
                &issuer_metadata,
                Some(oauth_metadata),
                credential_offer.grants,
                &credential_offer.credential_configuration_ids,
                None,
            )
            .await?;

        Ok(InvitationResponseEnum::Credential {
            interaction_id,
            tx_code,
            key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            ecosystem_artifact: ProtocolArtifact::HolderIssuanceInvitation {
                issuer_metadata: issuer_metadata.into(),
                credential_configuration_ids: credential_offer.credential_configuration_ids,
            },
        })
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        tx_code: Option<String>,
        credential_configuration_ids: Vec<String>,
    ) -> Result<IssuanceAcceptResult, IssuanceProtocolError> {
        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;
        let configurations =
            interaction_data.selected_configurations(&credential_configuration_ids);
        if configurations.is_empty() {
            return Err(IssuanceProtocolError::Failed(
                "no credential configuration selected".to_string(),
            ));
        }

        let mut autogenerated_bindings = vec![];
        let result = self
            .holder_accept_offer(
                &interaction,
                &mut interaction_data,
                configurations,
                holder_binding.as_ref(),
                tx_code,
                &mut autogenerated_bindings,
            )
            .await;

        let used_identifiers = result
            .iter()
            .flat_map(|accepted| accepted.issued.iter())
            .flat_map(|response| {
                std::iter::once(&response.main_credential.credential)
                    .chain(response.batch_items.iter().map(|item| &item.credential))
            })
            .filter_map(|credential| credential.holder_identifier.as_ref())
            .map(|identifier| identifier.id())
            .collect();
        if let Err(delete_error) = self
            .delete_unused_autogenerated_bindings(&autogenerated_bindings, used_identifiers)
            .await
        {
            tracing::warn!(%delete_error, "Failed to delete auto-generated holder bindings");
        }
        let result = result?;

        self.save_interaction_data(interaction.id, &interaction_data)
            .await?;
        Ok(result)
    }

    async fn regroup_configurations(
        &self,
        interaction_id: InteractionId,
        configuration_parents: HashMap<String, CredentialId>,
    ) -> Result<(), IssuanceProtocolError> {
        if configuration_parents.is_empty() {
            return Ok(());
        }
        // Acceptance already persisted tokens, notification IDs and exact schema formats.
        // Reload the latest data so regrouping changes only the requested parent associations.
        let interaction = self
            .interaction_repository
            .get_interaction(&interaction_id, None)
            .await
            .error_while("getting interaction to regroup")?;
        let mut data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;
        for (configuration_id, parent_id) in configuration_parents {
            let configuration = data.configuration_mut(&configuration_id).ok_or_else(|| {
                IssuanceProtocolError::Failed(format!(
                    "Unknown credential configuration: {configuration_id}"
                ))
            })?;
            if configuration.credential_id.is_none() {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Credential configuration {configuration_id} was not issued"
                )));
            }
            configuration.credential_id = Some(parent_id);
        }
        self.save_interaction_data(interaction_id, &data).await
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        let (main_credential, rejected_format) = if credential.r#type == CredentialType::BatchItem {
            let parent = credential.parent.as_required_ref().await?;
            let format_id = credential.format.id_opt().ok_or_else(|| {
                IssuanceProtocolError::Failed("Missing CredentialSchemaFormat".to_string())
            })?;
            if !self
                .batch_format_is_rejected(parent.id, Some(format_id))
                .await?
            {
                // Only a single item of a batch with others of the same format has been rejected.
                // The issuer will not be notified, and the format will still be refreshed.
                return Ok(());
            }
            (parent.to_owned(), Some(format_id))
        } else {
            (credential, None)
        };
        let interaction = main_credential
            .interaction
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .as_ref()
            .await?
            .to_owned();

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let notification_endpoint = match &interaction_data.notification_endpoint {
            Some(value) => value.clone(),
            None => {
                // if there's no notification endpoint specified by the issuer, we cannot notify the deletion
                tracing::info!("No notification_endpoint provided by issuer");
                return Ok(());
            }
        };
        let notifications: Vec<_> = interaction_data
            .configurations_for_credential(main_credential.id)
            .filter(|configuration| {
                rejected_format.is_none_or(|format_id| {
                    configuration.credential_schema_format_id == Some(format_id)
                        || (configuration.credential_schema_format_id.is_none()
                            && interaction_data.credential_configurations.len() == 1)
                })
            })
            .filter_map(|configuration| {
                configuration.notification_id.as_ref().map(|id| {
                    (
                        configuration.credential_configuration_id.clone(),
                        id.clone(),
                    )
                })
            })
            .collect();
        if notifications.is_empty() {
            tracing::info!("No notification_id saved for credential");
            return Ok(());
        }

        let organisation_id = interaction.organisation.id();

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, organisation_id, &mut interaction_data)
            .await?;

        let mut failures = vec![];
        for (configuration_id, notification_id) in notifications {
            if let Err(error) = self
                .send_notification(
                    NotificationRequest {
                        notification_id,
                        event: NotificationEvent::CredentialDeleted,
                        event_description: None,
                    },
                    notification_endpoint.as_str(),
                    access_token.expose_secret(),
                )
                .await
            {
                failures.push(format!("{configuration_id}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(IssuanceProtocolError::Failed(format!(
                "Credential deletion notifications failed: {}",
                failures.join("; ")
            )))
        }
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
        let mut url = Url::parse(&format!("{}://", self.params.url_scheme))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_schema = credential.schema.as_ref().await?;

        let formats = if let Some(previous_interaction) = &credential.interaction {
            let previous_interaction = previous_interaction.as_ref().await?;
            let previous_data: OpenID4VCIIssuerInteractionDataDTO =
                deserialize_interaction_data(previous_interaction.data.as_ref())?;
            previous_data.formats
        } else {
            None
        };
        let mut offered_formats = credential_schema.formats.as_ref().await?.to_owned();
        if let Some(formats) = &formats {
            offered_formats.retain(|format| formats.contains(&format.id));
        }

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))?;

        let interaction_id: InteractionId = Uuid::new_v4().into();
        let mut query = if self.params.credential_offer_by_value {
            let identifier_id = credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "issuer_identifier missing".to_string(),
                ))?
                .id();

            let offer = create_credential_offer(
                protocol_base_url,
                &credential.protocol,
                &interaction_id.to_string(),
                &credential_schema,
                &offered_formats,
                identifier_id,
            )?;

            let offer_string = serde_json::to_string(&offer)?;

            let mut query = url.query_pairs_mut();
            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
            query
        } else {
            let offer_url = get_credential_offer_url(protocol_base_url.to_owned(), credential)?;
            let mut query = url.query_pairs_mut();
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
            query
        };
        let url = query.finish().to_string();

        let transaction_code = credential_schema
            .transaction_code
            .as_ref()
            .map(generate_transaction_code);

        let interaction_data = Some(serialize_interaction_data(
            &OpenID4VCIIssuerInteractionDataDTO {
                pre_authorized_code_used: false,
                access_token_hash: vec![],
                access_token_expires_at: None,
                refresh_token_hash: None,
                refresh_token_expires_at: None,
                notification_ids: Default::default(),
                transaction_code: transaction_code.to_owned(),
                formats,
            },
        )?);

        let expires_at =
            Some(crate::clock::now_utc() + self.params.pre_authorized_code_expires_in_seconds);

        Ok(ShareResponse {
            url,
            interaction_id,
            interaction_data,
            expires_at,
            transaction_code,
        })
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        format_id: CredentialSchemaFormatId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SerializedCredential, IssuanceProtocolError> {
        let mut credential = self
            .credential_repository
            .get_credential(credential_id)
            .await
            .error_while("getting credential")?;

        if credential.r#type == CredentialType::BatchItem {
            // backfill claims for batch items, as these are only stored on the parent
            let parent = credential
                .parent
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "batch item {} is missing parent id",
                    credential.id
                )))?;
            // materialized on purpose: cloning the relation would alias the parent's claims
            let parent_claims = parent.as_ref().await?.claims.as_ref().await?.to_owned();
            credential.claims = parent_claims.into();
        }

        credential.holder_identifier = Some(holder_identifier.clone().into());

        let credential_schema = credential.schema.as_ref().await?.to_owned();
        let credential_state = credential.state;

        let formats = credential_schema.formats.as_ref().await?;
        let format = formats
            .into_iter()
            .find(|format| format.id == format_id)
            .ok_or(IssuanceProtocolError::Failed(
                "credential_schema format missing".to_string(),
            ))?;

        let credential_format_type = self
            .config
            .format
            .get_fields(&format.format)
            .error_while("getting format config")?
            .r#type;

        self.validate_credential_issuable(
            credential_id,
            &credential_state,
            &format.format,
            credential_format_type,
            credential_schema.batch_size.is_some(),
        )
        .await?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format.format)?;

        let revocation_method = match credential_schema.revocation_method_id(formatter.as_ref()) {
            Some(method_id) => Some(self.revocation_provider.get_revocation_method(method_id)?),
            None => None,
        };

        let credential_status = match revocation_method.as_deref() {
            Some(method) => method
                .add_issued_credential(&credential)
                .await
                .error_while("adding issued credential")?
                .into_iter()
                .map(|revocation_info| revocation_info.credential_status)
                .collect(),
            None => vec![],
        };

        let key = credential
            .key
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing key".to_string()))?
            .as_ref()
            .await?;

        let issuer_identifier = credential
            .issuer_identifier
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "missing issuer identifier".to_string(),
            ))?
            .as_ref()
            .await?;

        let auth_fn = self.key_provider.get_signature_provider(
            &key,
            self.jwk_key_id_from_identifier(&issuer_identifier, &key)
                .await?,
            self.key_algorithm_provider.clone(),
        )?;

        let core_base_url = self.base_url.as_ref().ok_or(IssuanceProtocolError::Failed(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;
        let holder_identifier_id = holder_identifier.id;
        let issuer_certificate = match credential.issuer_certificate.as_ref() {
            Some(certificate) => Some(certificate.as_ref().await?.to_owned()),
            None => first_certificate(&issuer_identifier)
                .await
                .error_while("getting issuer certificate")?,
        };
        let credential_data = CredentialData {
            credential: unsigned_credential(
                &credential,
                core_base_url,
                credential_status,
                &credential_schema,
                format,
                &self.config,
            )
            .await
            .error_while("creating credential")?,
            holder_identifier: Some(holder_identifier),
            holder_key_id: Some(holder_key_id),
            issuer_certificate,
        };

        let token = formatter
            .format_credential(credential_data, auth_fn)
            .await
            .error_while("formatting credential")?;

        let credential_blob_id = self.upsert_credential_blob(&credential, &token).await?;
        self.credential_repository
            .update_credential(
                *credential_id,
                get_issued_credential_update(credential_blob_id, holder_identifier_id),
            )
            .await
            .error_while("updating credential")?;

        Ok(token)
    }

    async fn holder_continue_issuance<'a>(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
    ) -> Result<ContinueIssuanceResponseDTO<'a>, IssuanceProtocolError> {
        let issuer_metadata = self
            .fetch_issuer_metadata(&continue_issuance_dto.credential_issuer, &organisation)
            .await?;

        let AuthorizationMetadata {
            token_endpoint,
            oauth_metadata,
            ..
        } = get_authorization_metadata(
            self.metadata_cache.as_ref(),
            issuer_metadata.metadata(),
            &continue_issuance_dto.credential_issuer,
            continue_issuance_dto.authorization_server.as_ref(),
        )
        .await?;

        let scope_to_id: HashMap<&String, &String> = issuer_metadata
            .metadata()
            .credential_configurations_supported
            .iter()
            .filter_map(|(id, c)| c.scope.as_ref().map(|s| (s, id)))
            .collect();

        let scope_credential_config_ids = continue_issuance_dto
            .scope
            .iter()
            .map(|s| {
                scope_to_id
                    .get(&s)
                    .map(|s| s.to_string())
                    .ok_or(IssuanceProtocolError::Failed(format!(
                        "Issuance requested scope doesnt exists: {s}"
                    )))
            })
            .collect::<Result<Vec<String>, IssuanceProtocolError>>()?;

        let all_credential_configuration_ids = [
            &scope_credential_config_ids[..],
            &continue_issuance_dto.credential_configuration_ids[..],
        ]
        .concat();

        let requires_wallet_instance_attestation =
            requires_wia(&oauth_metadata.token_endpoint_auth_methods_supported);

        let PrepareIssuanceSuccess {
            interaction_id,
            key_storage_security,
            key_algorithms,
        } = self
            .prepare_issuance_interaction(
                organisation,
                token_endpoint,
                &issuer_metadata,
                Some(oauth_metadata),
                Grants::AuthorizationCode(AuthorizationCodeGrant {
                    issuer_state: None, // issuer state was used at the authorization request stage so it is not relevant anymore
                    authorization_server: continue_issuance_dto.authorization_server.to_owned(),
                }),
                &all_credential_configuration_ids,
                Some(continue_issuance_dto),
            )
            .await?;

        Ok(ContinueIssuanceResponseDTO {
            interaction_id,
            key_storage_security_levels: key_storage_security,
            key_algorithms,
            requires_wallet_instance_attestation,
            protocol: self.config_id.to_owned(),
            ecosystem_artifact: ProtocolArtifact::HolderIssuanceInvitation {
                issuer_metadata: issuer_metadata.into(),
                credential_configuration_ids: all_credential_configuration_ids,
            },
        })
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        let mut features = vec![];
        if !self.params.swiyu_mode {
            features.push(Features::SupportsRejection);
        }
        if self.params.common.webhook_task.is_some() {
            features.push(Features::SupportsWebhooks);
        }

        let (did_methods, supported_encryption_algorithms) = if self.params.swiyu_mode {
            (
                vec![ConfigDidType::Tdw, ConfigDidType::Webvh],
                // the swiyu iOS app fails on parsing encryption algorithms it does not support
                vec![EncryptionAlgorithm::A128GCM, EncryptionAlgorithm::A256GCM],
            )
        } else {
            (
                vec![
                    ConfigDidType::Key,
                    ConfigDidType::Jwk,
                    ConfigDidType::Web,
                    ConfigDidType::Tdw,
                    ConfigDidType::Webvh,
                ],
                vec![
                    EncryptionAlgorithm::A128GCM,
                    EncryptionAlgorithm::A256GCM,
                    EncryptionAlgorithm::A128CBCHS256,
                    EncryptionAlgorithm::A256CBCHS512,
                ],
            )
        };

        IssuanceProtocolCapabilities {
            features,
            did_methods,
            supported_encryption_algorithms,
        }
    }

    fn protocol_base_url(&self) -> Option<String> {
        self.protocol_base_url.clone()
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError> {
        let enc_values_supported = self.get_capabilities().supported_encryption_algorithms;

        let prepared_metadata = self.prepare_issuer_metadata(credential_schema_id).await?;
        let issuer_info = self
            .get_etsi_issuer_info(issuer_identifier, &prepared_metadata.schema)
            .await?;

        let translations = issuer_identifier
            .translations
            .as_ref()
            .await
            .error_while("loading issuer identifier translations")?
            .to_owned();
        let logo_uri = crate::mapper::resolve_identifier_logo(
            &*self.blob_storage_provider,
            issuer_identifier.logo,
        )
        .await
        .error_while("resolving issuer identifier logo")?;
        let issuer_display = build_issuer_display(
            &issuer_identifier.name,
            &translations,
            logo_uri.as_deref(),
            &self.config.global_settings.default_language,
        );

        create_issuer_metadata_response(
            protocol_id,
            issuer_identifier,
            prepared_metadata,
            issuer_info,
            self.credential_request_encryption(issuer_identifier, enc_values_supported.clone())
                .await?,
            self.credential_response_encryption(enc_values_supported),
            issuer_display,
        )
        .map_err(OpenIDIssuanceError::OpenID4VCI)
        .map_err(Into::into)
    }

    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<IssuanceRefreshResponse>, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;
        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("deserializing interaction data")?;

        // MSO refresh: create no new credentials, request single credential and update the credential blob/state
        let updated_credential = match update_credential {
            Some(credential_id) => Some(
                self.credential_repository
                    .get_credential(&credential_id)
                    .await
                    .error_while("getting credential")?,
            ),
            None => None,
        };
        let configurations = self
            .select_refresh_configurations(
                interaction,
                &interaction_data,
                updated_credential.as_ref(),
            )
            .await?;
        if configurations.is_empty() {
            return Err(IssuanceProtocolError::RefreshNotPossible);
        }

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, organisation.id, &mut interaction_data)
            .await?;

        let mut autogenerated_bindings = vec![];
        let result = async {
            let mut requested_credentials = Vec::with_capacity(configurations.len());
            for refresh in configurations {
                requested_credentials.extend(
                    self.prepare_requested_credentials(
                        &interaction_data,
                        vec![refresh.configuration],
                        refresh.holder_binding.as_ref(),
                        &organisation,
                        &mut autogenerated_bindings,
                    )
                    .await?,
                );
            }
            // the keys of every configuration are attested in one wallet provider round trip
            self.prepare_wallet_attestations(
                &interaction_data,
                &mut requested_credentials,
                organisation.id,
                &[AttestationType::KeyAttestation],
            )
            .await?;

            // a configuration that fails does not stop the others, unless none is refreshed
            let mut refreshed = vec![];
            let mut failures = vec![];
            for requested in requested_credentials {
                let credential_configuration_id = requested
                    .configuration
                    .credential_configuration_id
                    .to_owned();
                match self
                    .holder_refresh_configuration(
                        interaction,
                        &mut interaction_data,
                        requested,
                        updated_credential.as_ref(),
                        &access_token,
                    )
                    .await
                {
                    Ok(credentials) => refreshed.push(IssuanceRefreshResponse {
                        credential_configuration_id,
                        credentials,
                    }),
                    Err(error) => {
                        tracing::warn!(
                            "Credential configuration {credential_configuration_id} not refreshed: {error}"
                        );
                        failures.push(error);
                    }
                }
            }
            if refreshed.is_empty()
                && let Some(error) = failures.into_iter().next()
            {
                return Err(error);
            }
            Ok::<_, IssuanceProtocolError>(refreshed)
        }
        .await;

        // the refreshed credentials are persisted already, their identifiers stay
        let used_identifiers = result
            .iter()
            .flatten()
            .flat_map(|response| &response.credentials)
            .filter_map(|credential| credential.holder_identifier.as_ref())
            .map(|identifier| identifier.id())
            .collect();
        self.delete_unused_autogenerated_bindings(&autogenerated_bindings, used_identifiers)
            .await?;

        let refreshed = result?;
        if updated_credential.is_none() {
            self.record_batch_refresh_history(&refreshed, &organisation)
                .await?;
        }
        Ok(refreshed)
    }

    fn config_name(&self) -> &str {
        &self.config_id
    }
}

struct RefreshConfiguration {
    configuration: HolderCredentialConfiguration,
    holder_binding: Option<HolderBindingInput>,
}

struct PrepareIssuanceSuccess {
    interaction_id: InteractionId,
    key_storage_security: Option<Vec<KeyStorageSecurity>>,
    key_algorithms: Option<Vec<String>>,
}

async fn resolve_credential_offer(
    client: &dyn HttpClient,
    invitation_url: Url,
) -> Result<CredentialOffer, IssuanceProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    match (
        query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY),
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY),
    ) {
        (Some(_), Some(_)) => Err(IssuanceProtocolError::Failed(format!(
            "Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"
        ))),
        (None, None) => Err(IssuanceProtocolError::Failed(
            "Missing credential offer param".to_string(),
        )),
        (Some(credential_offer_value), None) => Ok(serde_json::from_str(credential_offer_value)?),
        (None, Some(credential_offer_reference)) => {
            let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "Failed decoding credential offer url {error}"
                ))
            })?;

            Ok(async {
                client
                    .get(credential_offer_url.as_str())
                    .send()
                    .await?
                    .error_for_status()?
                    .json()
            }
            .await
            .error_while("fetching offer")?)
        }
    }
}

#[expect(clippy::large_enum_variant)]
enum IssuerMetadataRepresentation {
    Unsigned(CredentialIssuerMetadata),
    Signed(DecomposedJwt<CredentialIssuerMetadata>),
}

impl IssuerMetadataRepresentation {
    fn metadata(&self) -> &CredentialIssuerMetadata {
        match &self {
            Self::Unsigned(metadata) => metadata,
            Self::Signed(jwt) => &jwt.payload.custom,
        }
    }
}

struct AuthorizationMetadata {
    token_endpoint: String,
    oauth_metadata: AuthorizationServerMetadata,
}

async fn get_authorization_metadata(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_metadata: &CredentialIssuerMetadata,
    credential_issuer: &str,
    authorization_server: Option<&String>,
) -> Result<AuthorizationMetadata, IssuanceProtocolError> {
    let authorization_server_url = get_authorization_server_url_from_issuer_metadata(
        issuer_metadata,
        credential_issuer,
        authorization_server,
    )?;

    let oauth_metadata_response: AuthorizationServerMetadata = fetch_metadata_json_with_fallback(
        fetcher,
        &authorization_server_url,
        "oauth-authorization-server",
    )
    .await
    .error_while("fetching authorization server metadata")?;

    let token_endpoint = oauth_metadata_response
        .token_endpoint
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing token_endpoint".to_string(),
        ))?
        .to_string();

    Ok(AuthorizationMetadata {
        token_endpoint,
        oauth_metadata: oauth_metadata_response,
    })
}

fn get_authorization_server_url_from_issuer_metadata(
    issuer_metadata: &CredentialIssuerMetadata,
    credential_issuer: &str,
    authorization_server_from_offer: Option<&String>,
) -> Result<Url, IssuanceProtocolError> {
    let server_url = if let Some(authorization_server_from_offer) = authorization_server_from_offer
    {
        if issuer_metadata
            .authorization_servers
            .as_ref()
            .is_none_or(|servers| !servers.contains(authorization_server_from_offer))
        {
            return Err(IssuanceProtocolError::InvalidRequest(format!(
                "Authorization server missing in issuer metadata: {authorization_server_from_offer}"
            )));
        }

        authorization_server_from_offer.to_owned()
    } else if let Some(authorization_servers) = &issuer_metadata.authorization_servers {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        // > When there are multiple entries in the array, the Wallet may be able to determine which Authorization Server to use by querying the metadata; for example, by examining the grant_types_supported values, the Wallet can filter the server to use based on the grant type it plans to use.
        // TODO (ONE-7915): try to pick correct server based on querying, until then just pick the first
        authorization_servers
            .first()
            .ok_or(IssuanceProtocolError::Failed(
                "Empty authorization servers".to_string(),
            ))?
            .to_owned()
    } else {
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.2
        // > If this parameter is omitted, the entity providing the Credential Issuer is also acting as the Authorization Server
        credential_issuer.to_string()
    };

    server_url.parse().map_err(|_| {
        IssuanceProtocolError::InvalidRequest(format!(
            "Invalid authorization_server url {server_url}",
        ))
    })
}

async fn fetch_metadata_json_with_fallback<T: DeserializeOwned>(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_url: &Url,
    well_known_path: &str,
) -> Result<T, IssuanceProtocolError> {
    let issuer_metadata_endpoint = prepend_well_known_path(issuer_url, well_known_path);
    Ok(match fetcher.fetch_json(&issuer_metadata_endpoint).await {
        Ok(response) => response,
        Err(err) => {
            let error_code = err.error_code();
            if error_code == ErrorCode::BR_0347 || error_code == ErrorCode::BR_0395 {
                let fallback_metadata_endpoint = append_well_known(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{issuer_metadata_endpoint}`, falling back to legacy endpoint `{fallback_metadata_endpoint}`: {err}"
                );
                fetcher
                    .fetch_json(&fallback_metadata_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?
            } else {
                Err(err).error_while("fetching metadata")?
            }
        }
    })
}

async fn fetch_metadata_jwt_with_fallback<T: DeserializeOwned + Debug>(
    fetcher: &dyn OpenIDMetadataFetcher,
    issuer_url: &Url,
    well_known_path: &str,
) -> Result<DecomposedJwt<T>, IssuanceProtocolError> {
    let issuer_metadata_endpoint = prepend_well_known_path(issuer_url, well_known_path);
    Ok(match fetcher.fetch_jwt(&issuer_metadata_endpoint).await {
        Ok(response) => response,
        Err(err) => {
            let error_code = err.error_code();
            if error_code == ErrorCode::BR_0347 || error_code == ErrorCode::BR_0395 {
                let fallback_metadata_endpoint = append_well_known(issuer_url, well_known_path)?;
                tracing::warn!(
                    "Failed to fetch from `{issuer_metadata_endpoint}`, falling back to legacy endpoint `{fallback_metadata_endpoint}`: {err}"
                );
                fetcher
                    .fetch_jwt(&fallback_metadata_endpoint)
                    .await
                    .error_while("fetching metadata from fallback URL")?
            } else {
                Err(err).error_while("fetching metadata")?
            }
        }
    })
}

fn prepend_well_known_path(credential_issuer: &Url, well_known_path_segment: &str) -> String {
    let origin = {
        let mut url = credential_issuer.clone();
        url.set_path("");
        url.to_string()
    };
    let path = match credential_issuer.path() {
        "/" => "", // do not append trailing slash for empty path
        path => path,
    };
    format!("{origin}.well-known/{well_known_path_segment}{path}")
}

fn append_well_known(credential_issuer: &Url, path: &str) -> Result<String, IssuanceProtocolError> {
    let mut url = credential_issuer.to_owned();
    url.path_segments_mut()
        .map_err(move |_| {
            IssuanceProtocolError::Failed(format!(
                "Invalid credential_issuer URL: {credential_issuer}",
            ))
        })?
        .push(".well-known")
        .extend(path.split("/"));

    Ok(url.to_string())
}

async fn create_and_store_interaction(
    interaction_repository: &dyn InteractionRepository,
    data: Vec<u8>,
    organisation: impl Into<Related<Organisation>>,
) -> Result<Interaction, IssuanceProtocolError> {
    let now = crate::clock::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    interaction_repository
        .create_interaction(interaction.clone())
        .await
        .error_while("creating interaction")?;

    Ok(interaction)
}

impl IdentifierTrustInformation {
    fn is_valid(&self, now: OffsetDateTime) -> bool {
        let valid_form = self.valid_from.map(|v| v <= now).unwrap_or(true);
        let valid_to = self.valid_to.map(|v| now <= v).unwrap_or(true);
        valid_form && valid_to
    }

    fn is_issuance_allowed_for(&self, schema_id: &str, format_type: &FormatType) -> bool {
        self.allowed_issuance_types
            .iter()
            .any(|sf| sf.is_allowed_for(schema_id, format_type))
    }
}

impl SchemaFormat {
    fn is_allowed_for(&self, schema_id: &str, format_type: &FormatType) -> bool {
        self.schema_id == schema_id && self.format == format_type_to_dcql_format(format_type)
    }
}
