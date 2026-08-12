//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::Arc;

use async_trait::async_trait;
use attestations::{AttestationType, requires_wia};
use indexmap::IndexMap;
use mapper::{
    credential_config_to_holder_signing_algs_and_key_storage_security, get_credential_offer_url,
    map_cryptographic_binding_methods_supported, map_proof_types_supported,
    parse_credential_issuer_params,
};
use model::{
    HolderInteractionData, OpenID4VCIFinal1Params, OpenID4VCIIssuerInteractionDataDTO,
    PreparedMetadata, TokenRequestWalletAttestationRequest, WalletAttestationResult,
};
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::jwe::decrypt_jwe_payload;
use proc_macros::Provider;
use proof_formatter::{OpenID4VCIProofJWTFormatter, PublicKeyInfo};
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use service::{
    create_credential_offer, create_issuer_metadata_response, credential_configuration_supported,
    get_protocol_base_url,
};
use shared_types::{
    BlobId, CredentialFormat, CredentialId, CredentialSchemaFormatId, CredentialSchemaId,
    InteractionId, OrganisationId, SerializedCredential,
};
use standardized_types::jwk::JwkUse;
use standardized_types::oauth2::attestation_based_client_auth::ChallengeResponse;
use standardized_types::oauth2::authorization_server_metadata::AuthorizationServerMetadata;
use standardized_types::oauth2::token::{
    TokenErrorCode, TokenErrorResponse, TokenRequest, TokenResponse,
};
use standardized_types::openid4vci::{
    AuthorizationCodeGrant, AuthorizationDetail, CredentialConfiguration, CredentialIssuerMetadata,
    CredentialOffer, CredentialRequest, CredentialRequestIdentifier, Grants, IssuerInfoAttestation,
    IssuerInfoAttestationFormat, NonceResponse, NotificationEvent, NotificationRequest,
    ProofTypeSupported, Proofs, ResponseEncryption,
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
    ContinueIssuanceResponseDTO, InvitationResponseEnum, IssuanceAcceptResponse, ShareResponse,
    SubmitIssuerResponse,
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
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::credential::{Credential, CredentialStateEnum, CredentialType};
use crate::model::credential_schema::{CredentialSchema, KeyStorageSecurity};
use crate::model::did::KeyRole;
use crate::model::history::TrustResolutionResult;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::model::identifier_trust_information::{IdentifierTrustInformation, SchemaFormat};
use crate::model::interaction::{Interaction, UpdateInteractionRequest};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::relation::Related;
use crate::proto::certificate_validator::CertificateValidator;
use crate::proto::credential_schema::importer::CredentialSchemaImporter;
use crate::proto::http_client::{HttpClient, Response, is_media_type};
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::key_verification::KeyVerification;
use crate::proto::session_provider::SessionProvider;
use crate::proto::wallet_instance::HolderWalletUnitProto;
use crate::proto::wrp_validator::WRPValidator;
use crate::proto::wrp_validator::model::{AccessCertificateResult, TrustMode};
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{
    CredentialData, CredentialStatus, VerificationFn,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::ecosystem::model::ProtocolArtifact;
use crate::provider::issuance_protocol::openid4vci_final1_0::jwe::build_jwe;
use crate::provider::issuance_protocol::openid4vci_final1_0::mapper_v2::credential_to_credential_detail_v2;
use crate::provider::key_algorithm::ecdsa::ecdsa_public_key_as_jwk;
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::provider_directory::InitializationError;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::history_repository::HistoryRepository;
use crate::repository::instance_repository::InstanceRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::credential::dto::CredentialAttestationBlobs;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::oid4vci_final1_0::dto::OpenID4VCICredentialResponseDTO;
use crate::util::key_selection::KeyFilter;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;

mod attestations;
mod holder_credentials;
mod jwe;
pub(crate) mod mapper;
mod mapper_v2;
pub mod model;
pub mod proof_formatter;
pub mod service;
#[cfg(test)]
mod test;
#[cfg(test)]
mod test_issuance;
mod trust;
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
    wrp_validator: Arc<dyn WRPValidator>,
    history_repository: Arc<dyn HistoryRepository>,
    session_provider: Arc<dyn SessionProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
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
        wrp_validator: Arc<dyn WRPValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Result<Self, InitializationError> {
        let params =
            serde_json::from_value(params).map_err(|err| InitializationError::InvalidParams {
                key: config_id.to_string(),
                source: err,
            })?;

        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
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
            wrp_validator,
            history_repository,
            session_provider,
            interaction_repository,
        })
    }

    #[expect(clippy::too_many_arguments)]
    pub fn new_with_custom_protocol_base_url(
        protocol_base_url: Option<String>,
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
        params: OpenID4VCIFinal1Params,
        config_id: String,
        holder_wallet_unit_proto: Arc<dyn HolderWalletUnitProto>,
        holder_wallet_unit_repository: Arc<dyn InstanceRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        wrp_validator: Arc<dyn WRPValidator>,
        history_repository: Arc<dyn HistoryRepository>,
        session_provider: Arc<dyn SessionProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Self {
        Self {
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
            wrp_validator,
            history_repository,
            session_provider,
            interaction_repository,
        }
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
        wallet_attestation_request: Option<TokenRequestWalletAttestationRequest>,
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
        let attestation_result = self
            .prepare_wallet_attestations(
                interaction_data,
                &[],
                organisation_id,
                &[AttestationType::WIA],
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

            if let Some(TokenRequestWalletAttestationRequest {
                wallet_attestation,
                wallet_attestation_pop,
            }) = attestation_result.wia_tokens
            {
                request = request
                    .header("OAuth-Client-Attestation", &wallet_attestation)
                    .header("OAuth-Client-Attestation-PoP", &wallet_attestation_pop);
            }

            request.send().await?.error_for_status()?.json()
        }
        .await
        .error_while("requesting token")?;

        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        if let Some(new_refresh_token) = token_response.refresh_token {
            let encrypted_refresh_token =
                encrypt_string(&new_refresh_token, &self.params.encryption).map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token = Some(encrypted_refresh_token);
            interaction_data.access_token_expires_at = token_response
                .refresh_token_expires_in
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }

        self.interaction_repository
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;

        Ok(token_response.access_token)
    }

    async fn holder_fetch_nonce(
        &self,
        interaction_data: &HolderInteractionData,
    ) -> Result<String, IssuanceProtocolError> {
        let nonce_endpoint =
            interaction_data
                .nonce_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "nonce endpoint is missing".to_string(),
                ))?;

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

        Ok(response.c_nonce)
    }

    /// Fetches a challenge from the attestation-based client authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
    async fn holder_fetch_challenge(
        &self,
        challenge_endpoint: &str,
    ) -> Result<String, IssuanceProtocolError> {
        let response: ChallengeResponse = async {
            self.client
                .get(challenge_endpoint)
                .send()
                .await?
                .error_for_status()?
                .json()
        }
        .await
        .error_while("fetching challenge")?;

        Ok(response.attestation_challenge)
    }

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
        holder_binding_inputs: &[HolderBindingInput],
        wua_proofs: Option<Vec<String>>,
        access_token: &SecretString,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        struct CredentialRequestHolderKey<'a> {
            pub identifier: &'a Identifier,
            pub key: &'a Key,
            pub wua_proof: Option<String>,
        }

        let holder_bindings: Vec<_> = if let Some(wua_proofs) = wua_proofs {
            if wua_proofs.len() != holder_binding_inputs.len() {
                return Err(IssuanceProtocolError::Failed(format!(
                    "Different number of WUA received: {}, requested: {}",
                    wua_proofs.len(),
                    holder_binding_inputs.len()
                )));
            }

            // we assume the WUA proofs came in the same order as the requested keys were sent
            holder_binding_inputs
                .iter()
                .zip(wua_proofs)
                .map(|(HolderBindingInput { identifier, key }, wua_proof)| {
                    CredentialRequestHolderKey {
                        identifier,
                        key,
                        wua_proof: Some(wua_proof),
                    }
                })
                .collect()
        } else {
            holder_binding_inputs
                .iter()
                .map(
                    |HolderBindingInput { identifier, key }| CredentialRequestHolderKey {
                        identifier,
                        key,
                        wua_proof: None,
                    },
                )
                .collect()
        };

        let nonce = self.holder_fetch_nonce(interaction_data).await?;

        let client_id = interaction_data
            .continue_issuance
            .as_ref()
            .map(|ci| &ci.client_id);

        let mut proofs = Vec::with_capacity(holder_bindings.len());
        for CredentialRequestHolderKey {
            identifier,
            key,
            wua_proof,
        } in holder_bindings
        {
            let public_key_info = self
                .public_key_info_from_meta_and_holder_binding(interaction_data, identifier, key)
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
                Some(nonce.to_owned()),
                wua_proof,
                auth_fn,
                client_id,
            )
            .await
            .error_while("formatting proof")?;

            proofs.push(proof_jwt);
        }

        let body = CredentialRequest {
            credential: CredentialRequestIdentifier::CredentialConfigurationId(
                interaction_data.credential_configuration_id.to_owned(),
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
            let issuer_key = request_encryption.jwks.keys.first().cloned().ok_or(
                IssuanceProtocolError::Failed(
                    "credential_request_encryption contains empty jwks".to_string(),
                ),
            )?;
            let encrypted = build_jwe(
                &payload,
                issuer_key,
                selected_encryption_alg,
                selected_compression_alg,
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
        interaction_data: &HolderInteractionData,
        identifier: &Identifier,
        key: &Key,
    ) -> Result<PublicKeyInfo, IssuanceProtocolError> {
        // Should be optional, but currently not supported by core.
        //
        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-12.2.4-2.11.2.4:
        // It MUST be present when Cryptographic Key Binding is required for a Credential, and omitted otherwise.
        // If absent, Cryptographic Key Binding is not required for this credential.
        let Some(methods) = &interaction_data.cryptographic_binding_methods_supported else {
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

    async fn create_holder_binding(
        &self,
        interaction_data: &HolderInteractionData,
        organisation: &Organisation,
    ) -> Result<Vec<HolderBindingInput>, IssuanceProtocolError> {
        let generate_binding = async || {
            autogenerate_holder_binding(
                interaction_data
                    .cryptographic_binding_methods_supported
                    .as_ref(),
                interaction_data.proof_types_supported.as_ref(),
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
                result.push(generate_binding().await?);
            }
            result
        } else {
            vec![generate_binding().await?]
        })
    }

    #[tracing::instrument(level = "debug", skip(self), err(level = "info"))]
    async fn fetch_issuer_metadata(
        &self,
        credential_issuer: &str,
        organisation_id: OrganisationId,
    ) -> Result<(IssuerMetadataRepresentation, TrustMode), IssuanceProtocolError> {
        let credential_issuer_endpoint: Url = credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::InvalidRequest(format!(
                "Invalid credential issuer url {credential_issuer}",
            ))
        })?;

        let trust_mode = self
            .wrp_validator
            .wallet_trust_mode(organisation_id)
            .await
            .error_while("checking wallet trust mode")?;

        let fetch_unsigned_metadata = async || {
            Ok::<_, IssuanceProtocolError>(IssuerMetadataRepresentation::Unsigned(
                fetch_metadata_json_with_fallback(
                    self.metadata_cache.as_ref(),
                    &credential_issuer_endpoint,
                    "openid-credential-issuer",
                )
                .await?,
            ))
        };

        if trust_mode == TrustMode::Disabled {
            return Ok((fetch_unsigned_metadata().await?, trust_mode));
        }

        let jwt_result = fetch_metadata_jwt_with_fallback(
            self.metadata_cache.as_ref(),
            &credential_issuer_endpoint,
            "openid-credential-issuer",
        )
        .await;

        if trust_mode == TrustMode::TrustOptional
            && let Err(err) = &jwt_result
        {
            tracing::warn!(
                "Failed to fetch signed issuer metadata, falling back to unsigned metadata: {err}"
            );
            return Ok((fetch_unsigned_metadata().await?, trust_mode));
        }
        let jwt = jwt_result?;

        self.validate_jwt(&jwt)
            .await
            .error_while("validating issuer metadata JWT")?;

        let Some(x5c) = jwt.header.x5c.as_ref() else {
            tracing::debug!("Issuer metadata signed via DID or JWK");

            if trust_mode == TrustMode::TrustMandatory {
                return Err(IssuanceProtocolError::Untrusted);
            }

            return Ok((IssuerMetadataRepresentation::Signed(jwt, None), trust_mode));
        };

        let access_certificate = if trust_mode != TrustMode::Disabled {
            let pem_chain = x5c_into_pem_chain(x5c).error_while("converting x5c")?;
            match self
                .wrp_validator
                .validate_access_certificate(&pem_chain, Some(organisation_id))
                .await
            {
                Ok(result) => Some((result, pem_chain)),
                // untrusted
                Err(err) if err.error_code() == ErrorCode::BR_0410 => {
                    if trust_mode == TrustMode::TrustMandatory {
                        return Err(IssuanceProtocolError::Untrusted);
                    }

                    None
                }
                Err(err) => {
                    return Err(err.error_while("validating access certificate").into());
                }
            }
        } else {
            None
        };

        Ok((
            IssuerMetadataRepresentation::Signed(jwt, access_certificate),
            trust_mode,
        ))
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
        trust_mode: TrustMode,
    ) -> Result<PrepareIssuanceSuccess, IssuanceProtocolError> {
        // We only support one credential at a time currently
        let configuration_id = configuration_ids.first().ok_or_else(|| {
            IssuanceProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

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

        let (
            access_certificate,
            registration_certificate,
            national_registry_data,
            relying_party_id,
            relying_party_name,
            national_registry_url,
            trust_resolution,
        ) = if trust_mode != TrustMode::Disabled
            && let IssuerMetadataRepresentation::Signed(jwt, Some(access_certificate)) =
                &issuer_metadata
        {
            match self
                .validate_trust(
                    credential_config,
                    &jwt.payload.custom,
                    organisation.id,
                    &access_certificate.0,
                )
                .await
            {
                Ok(trust::TrustInfo {
                    registration_certificate,
                    national_registry_data,
                    relying_party_name,
                }) => (
                    Some(access_certificate.1.to_owned()),
                    registration_certificate,
                    national_registry_data,
                    Some(access_certificate.0.relying_party_id.clone()),
                    Some(relying_party_name),
                    access_certificate.0.registry_url.clone(),
                    TrustResolutionResult::Trusted,
                ),
                Err(err) => {
                    if trust_mode == TrustMode::TrustMandatory {
                        return Err(err);
                    } else {
                        tracing::info!(%err, "Trust validation failure");
                        (
                            None,
                            None,
                            None,
                            None,
                            None,
                            None,
                            TrustResolutionResult::Untrusted,
                        )
                    }
                }
            }
        } else {
            let trust_resolution = match trust_mode {
                TrustMode::TrustMandatory => {
                    return Err(IssuanceProtocolError::Untrusted);
                }
                TrustMode::TrustOptional => TrustResolutionResult::Untrusted,
                TrustMode::Disabled => TrustResolutionResult::Unknown,
            };
            (None, None, None, None, None, None, trust_resolution)
        };

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
            credential_signing_alg_values_supported: credential_config
                .credential_signing_alg_values_supported
                .clone(),
            cryptographic_binding_methods_supported: credential_config
                .cryptographic_binding_methods_supported
                .clone(),
            proof_types_supported: credential_config.proof_types_supported.clone(),
            token_endpoint_auth_methods_supported,
            client_attestation_pop_signing_alg_values_supported,
            credential_metadata: credential_config.credential_metadata.clone(),
            credential_request_encryption: issuer_metadata
                .metadata()
                .credential_request_encryption
                .clone(),
            credential_response_encryption: issuer_metadata
                .metadata()
                .credential_response_encryption
                .clone(),
            credential_configuration_id: configuration_id.to_owned(),
            notification_id: None,
            protocol: self.config_id.to_owned(),
            format: credential_config.format.to_owned(),
            access_certificate,
            registration_certificate,
            national_registry_url,
            national_registry_data,
            relying_party_name,
            trust_resolution,
            trust_mode,
            relying_party_id,
            disclosure_policy: credential_config.disclosure_policy.clone(),
        };
        let data = serialize_interaction_data(&holder_data)?;

        let interaction =
            create_and_store_interaction(self.interaction_repository.as_ref(), data, organisation)
                .await?;
        let (key_algorithms, key_storage_security) =
            credential_config_to_holder_signing_algs_and_key_storage_security(
                self.key_algorithm_provider.as_ref(),
                credential_config,
            );
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
                .filter(|ti| ti.is_issuance_allowed_for(&format.schema_id, &format_type));

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
                    schema.key_storage_security.map(Into::into),
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
                    .insert(format.schema_id.to_owned(), configuration);
            }
        }

        Ok(PreparedMetadata {
            protocol_base_url,
            schema,
            credential_configurations_supported,
        })
    }

    async fn map_to_credential_data(
        &self,
        format_id: CredentialSchemaFormatId,
        credential: &Credential,
        credential_status: Vec<CredentialStatus>,
        core_base_url: &str,
    ) -> Result<CredentialData, IssuanceProtocolError> {
        let schema = credential.schema.as_ref().await?;
        let schema_formats = schema.formats.as_ref().await?;
        let schema_format = schema_formats.iter().find(|f| f.id == format_id).ok_or(
            IssuanceProtocolError::Failed("missing credential schema format".to_string()),
        )?;
        let mappings = schema_format.claim_mappings.as_ref().await?;
        if !mappings.is_empty() {
            return credential_to_credential_detail_v2(
                credential,
                &schema,
                schema_format,
                &self.config,
                core_base_url,
                credential_status,
            )
            .await;
        }
        let credential_detail = credential_detail_response_from_model(
            credential.clone(),
            &self.config,
            CredentialAttestationBlobs::default(),
            None,
            None,
            self.credential_repository.as_ref(),
            self.formatter_provider.as_ref(),
        )
        .await
        .error_while("creating credential detail")?;

        let credential_data = credential_data_from_credential_detail_response(
            credential_detail,
            credential,
            core_base_url,
            credential_status,
            vcdm_v2_base_context(None),
            &schema,
            schema_format,
            &self.config,
        )
        .await
        .error_while("getting credential data")?;
        Ok(credential_data)
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

        let (issuer_metadata, trust_mode) = self
            .fetch_issuer_metadata(&credential_offer.credential_issuer, organisation.id)
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
                trust_mode,
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
    ) -> Result<IssuanceAcceptResponse, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let holder_binding = if let Some(holder_binding) = holder_binding {
            vec![holder_binding]
        } else {
            self.create_holder_binding(&interaction_data, &organisation)
                .await?
        };

        let holder_binding_keys: Vec<_> = holder_binding.iter().map(|b| &b.key).collect();
        let attestation_result = self
            .prepare_wallet_attestations(
                &interaction_data,
                &holder_binding_keys,
                organisation.id,
                &[AttestationType::WIA, AttestationType::WUA],
            )
            .await?;

        let token_response = self
            .holder_fetch_token(&interaction_data, tx_code, attestation_result.wia_tokens)
            .await?;

        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        interaction_data.refresh_token = token_response
            .refresh_token
            .map(|token| encrypt_string(&token, &self.params.encryption))
            .transpose()
            .map_err(|err| {
                IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
            })?;
        interaction_data.refresh_token_expires_at = token_response
            .refresh_token_expires_in
            .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());

        let credential_response = self
            .holder_request_credential(
                &interaction_data,
                &holder_binding,
                attestation_result.wua_proofs,
                &token_response.access_token,
            )
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        let result = self
            .holder_process_accepted_credentials(
                credential_response,
                &interaction_data,
                holder_binding,
                &organisation,
                &interaction,
            )
            .await;

        interaction_data.credential_metadata = None;
        interaction_data.notification_id = notification_id.clone();
        self.interaction_repository
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                    ..Default::default()
                },
            )
            .await
            .error_while("updating interaction")?;

        if let (Some(notification_id), Some(notification_endpoint)) =
            (notification_id, interaction_data.notification_endpoint)
        {
            let notification = match &result {
                Ok(_) => NotificationRequest {
                    notification_id,
                    event: NotificationEvent::CredentialAccepted,
                    event_description: None,
                },
                Err(err) => NotificationRequest {
                    notification_id,
                    event: NotificationEvent::CredentialFailure,
                    event_description: Some(err.to_string()),
                },
            };

            if let Err(error) = self
                .send_notification(
                    notification,
                    notification_endpoint.as_str(),
                    token_response.access_token.expose_secret(),
                )
                .await
            {
                tracing::warn!(%error, "Notification failure");
            }
        }

        result
    }

    async fn holder_reject_credential(
        &self,
        credential: Credential,
    ) -> Result<(), IssuanceProtocolError> {
        let interaction = credential
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
        let notification_id = match &interaction_data.notification_id {
            Some(value) => value.clone(),
            None => {
                tracing::info!("No notification_id saved for interaction");
                return Ok(());
            }
        };

        let organisation_id = interaction.organisation.id();

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, organisation_id, &mut interaction_data)
            .await?;

        self.send_notification(
            NotificationRequest {
                notification_id,
                event: NotificationEvent::CredentialDeleted,
                event_description: None,
            },
            notification_endpoint.as_str(),
            access_token.expose_secret(),
        )
        .await
    }

    async fn issuer_share_credential(
        &self,
        credential: &Credential,
    ) -> Result<ShareResponse, IssuanceProtocolError> {
        let interaction_id: InteractionId = Uuid::new_v4().into();

        let mut url = Url::parse(&format!("{}://", self.params.url_scheme))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_schema = credential.schema.as_ref().await?;

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))?;

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
                identifier_id,
            )
            .await?;

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
                notification_id: None,
                transaction_code: transaction_code.to_owned(),
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
        let mut credential_data = self
            .map_to_credential_data(format_id, &credential, credential_status, core_base_url)
            .await?;

        credential_data.holder_identifier = Some(holder_identifier);
        credential_data.holder_key_id = Some(holder_key_id);
        credential_data.issuer_certificate =
            if let Some(cert) = credential.issuer_certificate.as_ref() {
                Some(cert.as_ref().await?.to_owned())
            } else if let IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) = &issuer_identifier.data
            {
                certificates.as_ref().await?.first().cloned()
            } else {
                None
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
        let (issuer_metadata, trust_mode) = self
            .fetch_issuer_metadata(&continue_issuance_dto.credential_issuer, organisation.id)
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
                trust_mode,
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
        let mut features = vec![Features::SupportsRejection];
        if self.params.common.webhook_task.is_some() {
            features.push(Features::SupportsWebhooks);
        }

        IssuanceProtocolCapabilities {
            features,
            did_methods: vec![
                ConfigDidType::Key,
                ConfigDidType::Jwk,
                ConfigDidType::Web,
                ConfigDidType::WebVh,
            ],
        }
    }

    async fn issuer_metadata(
        &self,
        protocol_id: &str,
        credential_schema_id: &CredentialSchemaId,
        issuer_identifier: &Identifier,
    ) -> Result<CredentialIssuerMetadata, IssuanceProtocolError> {
        let prepared_metadata = self.prepare_issuer_metadata(credential_schema_id).await?;
        let issuer_info = self
            .get_etsi_issuer_info(issuer_identifier, &prepared_metadata.schema)
            .await?;

        create_issuer_metadata_response(
            protocol_id,
            issuer_identifier,
            prepared_metadata,
            issuer_info,
        )
        .map_err(OpenIDIssuanceError::OpenID4VCI)
        .map_err(Into::into)
    }

    async fn holder_refresh_credential(
        &self,
        interaction: &Interaction,
        update_credential: Option<CredentialId>,
    ) -> Result<Vec<CredentialId>, IssuanceProtocolError> {
        let organisation = interaction.organisation.as_ref().await?;
        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())
                .error_while("deserializing interaction data")?;

        let (holder_binding_inputs, updated_credential) =
            if let Some(credential_id) = update_credential {
                // MSO refresh: create no new credentials, request single credential and update the credential blob/state

                let credential = self
                    .credential_repository
                    .get_credential(&credential_id)
                    .await
                    .error_while("getting credential")?;

                // reusing old key for holder binding
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

                (
                    vec![HolderBindingInput { identifier, key }],
                    Some(credential),
                )
            } else {
                (
                    self.create_holder_binding(&interaction_data, &organisation)
                        .await?,
                    None,
                )
            };

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, organisation.id, &mut interaction_data)
            .await?;

        let attested_keys: Vec<_> = holder_binding_inputs.iter().map(|b| &b.key).collect();
        let attestation_result = self
            .prepare_wallet_attestations(
                &interaction_data,
                &attested_keys,
                organisation.id,
                &[AttestationType::WUA],
            )
            .await?;

        let response = self
            .holder_request_credential(
                &interaction_data,
                &holder_binding_inputs,
                attestation_result.wua_proofs,
                &access_token,
            )
            .await?;

        let notification_id = response.notification_id.to_owned();
        if let Some(notification_id) = notification_id.to_owned() {
            interaction_data.notification_id = Some(notification_id);
            self.interaction_repository
                .update_interaction(
                    interaction.id,
                    UpdateInteractionRequest {
                        data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                        ..Default::default()
                    },
                )
                .await
                .error_while("updating interaction")?;
        }

        let result = self
            .holder_process_refresh(
                &interaction_data,
                holder_binding_inputs,
                response,
                &organisation,
                updated_credential,
                interaction,
            )
            .await;

        if let (Err(err), Some(notification_id), Some(notification_endpoint)) = (
            &result,
            notification_id,
            interaction_data.notification_endpoint,
        ) {
            let notification = NotificationRequest {
                notification_id,
                event: NotificationEvent::CredentialFailure,
                event_description: Some(err.to_string()),
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

    fn config_name(&self) -> &str {
        &self.config_id
    }
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
    Signed(
        DecomposedJwt<CredentialIssuerMetadata>,
        Option<(AccessCertificateResult, String)>,
    ),
}

impl IssuerMetadataRepresentation {
    fn metadata(&self) -> &CredentialIssuerMetadata {
        match &self {
            Self::Unsigned(metadata) => metadata,
            Self::Signed(jwt, _) => &jwt.payload.custom,
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
