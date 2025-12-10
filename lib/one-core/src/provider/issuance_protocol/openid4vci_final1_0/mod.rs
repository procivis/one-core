//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::utilities::generate_alphanumeric;
use one_dto_mapper::convert_inner;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shared_types::{
    BlobId, CertificateId, CredentialFormat, CredentialId, DidValue, HolderWalletUnitId,
    IdentifierId,
};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::TxCodeError;
use super::mapper::{get_issued_credential_update, interaction_from_handle_invitation};
use super::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, KeyStorageSecurityLevel, ShareResponse,
    SubmitIssuerResponse, UpdateResponse,
};
use super::openid4vci_final1_0::mapper::{
    credential_config_to_holder_signing_algs_and_key_storage_security, get_credential_offer_url,
    interaction_data_to_accepted_key_storage_security, parse_credential_issuer_params,
};
use super::openid4vci_final1_0::model::{
    ChallengeResponseDTO, HolderInteractionData, OAuthAuthorizationServerMetadata,
    OpenID4VCIAuthorizationCodeGrant, OpenID4VCICredentialRequestDTO, OpenID4VCIFinal1Params,
    OpenID4VCIGrants, OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use super::openid4vci_final1_0::proof_formatter::OpenID4VCIProofJWTFormatter;
use super::openid4vci_final1_0::service::{create_credential_offer, get_protocol_base_url};
use super::{
    HolderBindingInput, IssuanceProtocol, IssuanceProtocolError, StorageAccess,
    deserialize_interaction_data, serialize_interaction_data,
};
use crate::config::core_config::{
    CoreConfig, DidType as ConfigDidType, FormatType, KeyAlgorithmType,
};
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, KeyStorageSecurity, LayoutType,
    UpdateCredentialSchemaRequest,
};
use crate::model::did::{Did, DidRelations, DidType, KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionId, UpdateInteractionRequest};
use crate::model::key::{Key, KeyRelations, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::proto::http_client::HttpClient;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::proto::wallet_unit::{HolderWalletUnitProto, IssueWalletAttestationRequest};
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::provider::caching_loader::openid_metadata::OpenIDMetadataFetcher;
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::mapper::autogenerate_holder_binding;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestIdentifier, OpenID4VCICredentialRequestProofs,
    OpenID4VCIFinal1CredentialOfferDTO, TokenRequestWalletAttestationRequest,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_security_level::provider::KeySecurityLevelProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::credential::dto::CredentialAttestationBlobs;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::MissingProviderError;
use crate::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
};
use crate::service::oid4vci_final1_0::service::prepare_preview_claims_for_offer;
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;
use crate::validator::key_security::match_key_security_level;
use crate::validator::validate_issuance_time;

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

pub(crate) struct OpenID4VCIFinal1_0 {
    client: Arc<dyn HttpClient>,
    metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
    credential_repository: Arc<dyn CredentialRepository>,
    key_repository: Arc<dyn KeyRepository>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
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
}

impl OpenID4VCIFinal1_0 {
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        metadata_cache: Arc<dyn OpenIDMetadataFetcher>,
        credential_repository: Arc<dyn CredentialRepository>,
        key_repository: Arc<dyn KeyRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
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
    ) -> Self {
        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            client,
            metadata_cache,
            credential_repository,
            key_repository,
            identifier_creator,
            validity_credential_repository,
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
            key_security_level_provider,
        }
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        format: &CredentialFormat,
        format_type: FormatType,
    ) -> Result<(), IssuanceProtocolError> {
        match (latest_state, format_type) {
            (CredentialStateEnum::Accepted, FormatType::Mdoc) => {
                let mdoc_validity_credential = self
                    .validity_credential_repository
                    .get_latest_by_credential_id(*credential_id, ValidityCredentialType::Mdoc)
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
                    .ok_or_else(|| {
                        IssuanceProtocolError::Failed(format!(
                            "Missing verifiable credential for MDOC: {credential_id}"
                        ))
                    })?;

                let can_be_updated_at = mdoc_validity_credential.created_date
                    + self.mso_minimum_refresh_time(format)?;

                if can_be_updated_at > OffsetDateTime::now_utc() {
                    return Err(IssuanceProtocolError::RefreshTooSoon);
                }
            }
            (CredentialStateEnum::Suspended, FormatType::Mdoc) => {
                return Err(IssuanceProtocolError::Suspended);
            }
            (CredentialStateEnum::Offered, _) => {}
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
        self.config
            .format
            .get::<mdoc_formatter::Params, _>(format)
            .map(|p| p.mso_minimum_refresh_time)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))
    }

    fn jwk_key_id_from_identifier(
        &self,
        issuer_identifier: &Identifier,
        key: &Key,
    ) -> Result<Option<String>, IssuanceProtocolError> {
        let Some(ref did) = issuer_identifier.did else {
            return Ok(None);
        };

        let related_did_key = did
            .find_key(&key.id, &KeyFilter::role_filter(KeyRole::AssertionMethod))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .ok_or_else(|| IssuanceProtocolError::Failed("Missing related key".to_string()))?;

        let issuer_jwk_key_id = did.verification_method_id(related_did_key);

        Ok(Some(issuer_jwk_key_id))
    }

    async fn holder_fetch_token(
        &self,
        interaction_data: &HolderInteractionData,
        tx_code: Option<String>,
        wallet_attestation_request: Option<TokenRequestWalletAttestationRequest>,
    ) -> Result<OpenID4VCITokenResponseDTO, IssuanceProtocolError> {
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
            OpenID4VCIGrants::PreAuthorizedCode(code) => {
                OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                    pre_authorized_code: code.pre_authorized_code.to_owned(),
                    tx_code,
                }
            }
            OpenID4VCIGrants::AuthorizationCode(_) => {
                let Some(data) = &interaction_data.continue_issuance else {
                    return Err(IssuanceProtocolError::Failed(
                        "continue_issuance data is missing".to_string(),
                    ));
                };
                OpenID4VCITokenRequestDTO::AuthorizationCode {
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
            .context("Invalid token_endpoint request")
            .map_err(IssuanceProtocolError::Transport)?;

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

        let response = request
            .send()
            .await
            .context("Error during token_endpoint response")
            .map_err(IssuanceProtocolError::Transport)?;

        if response.status.is_client_error() && has_sent_tx_code {
            #[derive(Deserialize)]
            struct ErrorResponse {
                error: OpenId4VciError,
            }

            #[derive(Deserialize)]
            #[serde(rename_all = "snake_case")]
            enum OpenId4VciError {
                InvalidGrant,
                InvalidRequest,
            }

            match serde_json::from_slice::<ErrorResponse>(&response.body).map(|r| r.error) {
                Ok(OpenId4VciError::InvalidGrant) => {
                    return Err(IssuanceProtocolError::TxCode(TxCodeError::IncorrectCode));
                }
                Ok(OpenId4VciError::InvalidRequest) => {
                    return Err(IssuanceProtocolError::TxCode(TxCodeError::InvalidCodeUse));
                }
                Err(_) => {}
            }
        }

        response
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)
    }

    async fn holder_reuse_or_refresh_token(
        &self,
        interaction_id: InteractionId,
        interaction_data: &mut HolderInteractionData,
        storage_access: &StorageAccess,
    ) -> Result<SecretString, IssuanceProtocolError> {
        let now = OffsetDateTime::now_utc();
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
            return Err(IssuanceProtocolError::Failed(
                "no refresh token saved".to_owned(),
            ));
        };

        if interaction_data
            .refresh_token_expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            // Expired refresh token
            return Err(IssuanceProtocolError::Failed(
                "expired refresh token".to_owned(),
            ));
        }

        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let token_response: OpenID4VCITokenResponseDTO = self
            .client
            .post(token_endpoint)
            .form(&[
                ("refresh_token", refresh_token.expose_secret().to_string()),
                ("grant_type", "refresh_token".to_string()),
            ])
            .context("form error")
            .map_err(IssuanceProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)?;

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

        storage_access
            .update_interaction(
                interaction_id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                },
            )
            .await
            .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

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

        let response: OpenID4VCINonceResponseDTO = self
            .client
            .post(nonce_endpoint.as_str())
            .send()
            .await
            .context("Error during nonce_endpoint response")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?;

        Ok(response.c_nonce)
    }

    /// Fetches a challenge from the attestation-based client authentication challenge endpoint
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-07#section-8>
    async fn holder_fetch_challenge(
        &self,
        challenge_endpoint: &str,
    ) -> Result<String, IssuanceProtocolError> {
        let response: ChallengeResponseDTO = self
            .client
            .get(challenge_endpoint)
            .send()
            .await
            .context("Error during challenge_endpoint response")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "Failed decoding challenge response json {error}"
                ))
            })?;

        Ok(response.attestation_challenge)
    }

    async fn holder_process_accepted_credential(
        &self,
        issuer_response: SubmitIssuerResponse,
        interaction_data: &HolderInteractionData,
        holder_binding: HolderBindingInput,
        storage_access: &StorageAccess,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        let format_type = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            Some(&issuer_response.credential),
        )
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let (format, formatter) = self
            .formatter_provider
            .get_formatter_by_type(format_type)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format_type} formatter not found"))
            })?;

        let mut credential = formatter
            .parse_credential(&issuer_response.credential)
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&credential.issuance_date, formatter.get_leeway())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let schema = credential
            .schema
            .as_mut()
            .ok_or(IssuanceProtocolError::Failed("Missing schema".to_string()))?;

        let metadata = interaction_data.credential_metadata.as_ref();
        let metadata_display = metadata
            .and_then(|metadata| metadata.display.as_ref())
            .and_then(|display| {
                display
                    .iter()
                    .find(|display| display.locale.as_ref().is_none_or(|locale| locale == "en"))
            });

        if let Some(name) = metadata_display.map(|display| display.name.to_owned()) {
            schema.name = name;
        }
        schema.format = format;
        schema.organisation = Some(organisation.to_owned());
        schema.layout_type = LayoutType::Card;
        schema.layout_properties = metadata_display.and_then(|display| display.to_owned().into());
        schema.key_storage_security = interaction_data
            .proof_types_supported
            .as_ref()
            .and_then(|map| map.get("jwt"))
            .and_then(|jwt| jwt.key_attestations_required.as_ref())
            .and_then(|att_list| {
                convert_inner(KeyStorageSecurityLevel::select_lowest(
                    &att_list.key_storage,
                ))
            });

        let identifier_updates = match credential.issuer_identifier.as_ref() {
            Some(Identifier {
                did: Some(did),
                r#type,
                ..
            }) if r#type == &IdentifierType::Did => {
                prepare_did_identifier(
                    did.did.to_owned(),
                    organisation,
                    storage_access,
                    self.did_method_provider.as_ref(),
                )
                .await?
            }
            Some(Identifier {
                certificates: Some(certificates),
                r#type,
                ..
            }) if r#type == &IdentifierType::Certificate => {
                prepare_certificate_identifier(
                    certificates.first().cloned(),
                    organisation,
                    storage_access,
                )
                .await?
            }
            Some(Identifier {
                key: Some(key),
                r#type,
                ..
            }) if r#type == &IdentifierType::Key => {
                prepare_key_identifier(key.to_owned(), organisation, storage_access).await?
            }
            _ => {
                return Err(IssuanceProtocolError::Failed(
                    "Invalid parsed issuer identifier".to_string(),
                ));
            }
        };

        credential.redirect_uri = issuer_response.redirect_uri.clone();
        credential.state = CredentialStateEnum::Accepted;
        credential.holder_identifier = Some(holder_binding.identifier);
        credential.key = Some(holder_binding.key);
        credential.protocol = self.config_id.to_owned();
        credential.interaction = Some(interaction.to_owned());
        if let Some(identifier) = credential.issuer_identifier.as_mut() {
            identifier.id = identifier_updates.issuer_identifier_id;
        }
        if let Some(issuer_certificate_id) = identifier_updates.issuer_certificate_id
            && let Some(certificate) = credential.issuer_certificate.as_mut()
        {
            certificate.id = issuer_certificate_id;
        }

        let credential_schema_updates = prepare_credential_schema(
            schema.to_owned(),
            organisation,
            storage_access,
            &mut credential,
        )
        .await?;

        Ok(UpdateResponse {
            result: issuer_response,
            create_identifier: identifier_updates.create_identifier,
            create_did: identifier_updates.create_did,
            create_certificate: identifier_updates.create_certificate,
            create_key: identifier_updates.create_key,
            update_credential_schema: credential_schema_updates.update,
            create_credential_schema: credential_schema_updates.create,
            update_credential: None,
            create_credential: Some(credential),
        })
    }

    async fn send_notification(
        &self,
        message: OpenID4VCINotificationRequestDTO,
        notification_endpoint: &str,
        access_token: &str,
    ) -> Result<(), IssuanceProtocolError> {
        let response = self
            .client
            .post(notification_endpoint)
            .bearer_auth(access_token)
            .json(&message)
            .context("json error")
            .map_err(IssuanceProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;

        response
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?;

        Ok(())
    }

    #[expect(clippy::too_many_arguments)]
    async fn holder_request_credential(
        &self,
        interaction_data: &HolderInteractionData,
        holder_did: Option<&DidValue>,
        holder_key: PublicKeyJwk,
        nonce: Option<String>,
        auth_fn: AuthenticationFn,
        access_token: &str,
        key_attestation: Option<String>,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let jwk = interaction_data
            .cryptographic_binding_methods_supported
            .as_ref()
            .and_then(|methods| {
                if let Some(holder_did) = holder_did
                    && methods
                        .iter()
                        .any(|method| &format!("did:{}", holder_did.method()) == method)
                {
                    None
                } else if methods.contains(&"jwk".to_string()) {
                    Some(holder_key.into())
                } else {
                    None
                }
            });

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url.to_owned(),
            jwk,
            nonce,
            key_attestation,
            auth_fn,
        )
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let body = OpenID4VCICredentialRequestDTO {
            credential: OpenID4VCICredentialRequestIdentifier::CredentialConfigurationId(
                interaction_data.credential_configuration_id.to_owned(),
            ),
            proofs: Some(OpenID4VCICredentialRequestProofs::Jwt(vec![proof_jwt])),
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint.as_str())
            .bearer_auth(access_token)
            .json(&body)
            .context("json error")
            .map_err(IssuanceProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;

        let response = response
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?;

        let response: OpenID4VCICredentialResponseDTO = response
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)?;

        Ok(SubmitIssuerResponse {
            credential: response
                .credentials
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing credential".to_string(),
                ))?
                .first()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing credential".to_string(),
                ))?
                .credential
                .to_owned(),
            redirect_uri: response.redirect_uri,
            notification_id: response.notification_id,
        })
    }

    async fn upsert_credential_blob(
        &self,
        credential: &Credential,
        token: &str,
    ) -> Result<BlobId, IssuanceProtocolError> {
        let db_blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)
            .await
            .ok_or_else(|| MissingProviderError::BlobStorage(BlobStorageType::Db.to_string()))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_blob_id = match credential.credential_blob_id {
            None => {
                let blob = Blob::new(token, BlobType::Credential);
                db_blob_storage
                    .create(blob.clone())
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
                blob.id
            }
            Some(blob_id) => {
                db_blob_storage
                    .update(
                        &blob_id,
                        UpdateBlobRequest {
                            value: Some(token.into()),
                        },
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
                blob_id
            }
        };
        Ok(credential_blob_id)
    }

    async fn create_holder_binding(
        &self,
        interaction_data: &HolderInteractionData,
        organisation: &Organisation,
    ) -> Result<HolderBindingInput, IssuanceProtocolError> {
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
    }
}

#[async_trait]
impl IssuanceProtocol for OpenID4VCIFinal1_0 {
    async fn holder_can_handle(&self, url: &Url) -> bool {
        if self.params.url_scheme != url.scheme() {
            return false;
        }

        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);
        if !query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
            && !query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY)
        {
            return false;
        }

        async {
            let credential_offer =
                resolve_credential_offer(self.client.as_ref(), url.to_owned()).await?;
            let credential_issuer: Url = credential_offer
                .credential_issuer
                .parse()
                .map_err(|_| IssuanceProtocolError::Failed("".to_string()))?;
            let metadata_url =
                prepend_well_known_path(&credential_issuer, "openid-credential-issuer");
            self.metadata_cache
                .fetch::<OpenID4VCIIssuerMetadataResponseDTO>(&metadata_url)
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))
        }
        .await
        .is_ok()
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
        handle_credential_invitation(
            url,
            organisation,
            &*self.client,
            &*self.metadata_cache,
            storage_access,
            redirect_uri,
            &self.config,
            self.config_id.to_owned(),
            &*self.key_algorithm_provider,
        )
        .await
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_binding: Option<HolderBindingInput>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<UpdateResponse, IssuanceProtocolError> {
        let organisation =
            interaction
                .organisation
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "organisation is None".to_string(),
                ))?;

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let holder_binding = if let Some(holder_binding) = holder_binding {
            holder_binding
        } else {
            self.create_holder_binding(&interaction_data, organisation)
                .await?
        };

        let key = &holder_binding.key;

        let wallet_attestation_required = interaction_data
            .token_endpoint_auth_methods_supported
            .as_ref()
            .unwrap_or(&vec![])
            .contains(&"attest_jwt_client_auth".to_string());

        let issuer_accepted_levels =
            interaction_data_to_accepted_key_storage_security(&interaction_data);
        let key_storage_security_level = if let Some(accepted_levels) = &issuer_accepted_levels {
            Some(
                match_key_security_level(
                    &key.storage_type,
                    accepted_levels,
                    &*self.key_security_level_provider,
                )
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
            )
        } else {
            None
        };

        let wallet_attestations_issuance_request =
            match (wallet_attestation_required, &key_storage_security_level) {
                (true, Some(key_storage_security_level)) => Some(
                    IssueWalletAttestationRequest::WuaAndWaa(key, *key_storage_security_level),
                ),
                (true, None) => Some(IssueWalletAttestationRequest::Waa),
                (false, Some(key_storage_security_level)) => Some(
                    IssueWalletAttestationRequest::Wua(key, *key_storage_security_level),
                ),
                (false, None) => None,
            };

        let wallet_attestations_issuance_response = match wallet_attestations_issuance_request {
            None => None,
            Some(wallet_attestation_request) => {
                let holder_wallet_unit_id = holder_wallet_unit_id.ok_or(
                    IssuanceProtocolError::Failed("holder wallet unit id is required".to_string()),
                )?;

                let wallet_attestation = self
                    .holder_wallet_unit_proto
                    .issue_wallet_attestations(&holder_wallet_unit_id, wallet_attestation_request)
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

                Some(wallet_attestation)
            }
        };

        let waa_and_proof = match (
            wallet_attestation_required,
            &wallet_attestations_issuance_response,
        ) {
            (true, Some(issuance_response)) => {
                let waa = issuance_response
                    .waa
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Wallet attestation is required".to_string(),
                    ))?;

                let challenge =
                    if let Some(challenge_endpoint) = &interaction_data.challenge_endpoint {
                        Some(self.holder_fetch_challenge(challenge_endpoint).await?)
                    } else {
                        None
                    };

                // Get the wallet unit's authentication key for signing the PoP
                // The PoP must be signed with the key that matches the cnf.jwk in the WAA
                let wallet_unit_auth_key = self
                    .holder_wallet_unit_proto
                    .get_authentication_key(&holder_wallet_unit_id.ok_or(
                        IssuanceProtocolError::Failed(
                            "holder wallet unit id is required for WAA PoP".to_string(),
                        ),
                    )?)
                    .await
                    .map_err(|e| {
                        IssuanceProtocolError::Failed(format!(
                            "Failed to get authentication key: {e}"
                        ))
                    })?;

                let signed_proof = create_wallet_unit_attestation_pop(
                    &*self.key_provider,
                    self.key_algorithm_provider.clone(),
                    &wallet_unit_auth_key,
                    &interaction_data.issuer_url,
                    challenge,
                )
                .await?;

                Ok(Some(TokenRequestWalletAttestationRequest {
                    wallet_attestation: waa.to_owned(),
                    wallet_attestation_pop: signed_proof,
                }))
            }
            (true, None) => Err(IssuanceProtocolError::Failed(
                "Wallet attestation is required".to_string(),
            )),
            (false, _) => Ok(None),
        }?;

        let key_attestations_required = key_storage_security_level.is_some();
        let wua_proof = match (
            key_attestations_required,
            &wallet_attestations_issuance_response,
        ) {
            (true, Some(issuance_response)) => {
                let wua = issuance_response
                    .wua
                    .first()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Key attestation is required".to_string(),
                    ))?;

                Ok(Some(wua.to_owned()))
            }
            (true, None) => Err(IssuanceProtocolError::Failed(
                "Key attestation is required".to_string(),
            )),
            (false, _) => Ok(None),
        }?;

        let token_response = self
            .holder_fetch_token(&interaction_data, tx_code, waa_and_proof)
            .await?;
        let nonce = self.holder_fetch_nonce(&interaction_data).await?;

        let encrypted_access_token =
            encrypt_string(&token_response.access_token, &self.params.encryption).map_err(
                |err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt access token: {err}"))
                },
            )?;
        interaction_data.access_token = Some(encrypted_access_token);
        interaction_data.access_token_expires_at =
            OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();

        // only mdoc credentials support refreshing, do not store refresh tokens otherwise
        if interaction_data.format == "mso_mdoc" {
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
        }

        let holder_jwk_key_id = if holder_binding.identifier.r#type == IdentifierType::Did {
            let did =
                holder_binding
                    .identifier
                    .did
                    .as_ref()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Missing identifier did".to_string(),
                    ))?;

            let related_key = did
                .find_key(
                    &holder_binding.key.id,
                    &KeyFilter::role_filter(KeyRole::Authentication),
                )
                .map_err(|err| {
                    IssuanceProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing did related key".to_string(),
                ))?;

            Some(did.verification_method_id(related_key))
        } else {
            None
        };

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, holder_jwk_key_id, self.key_algorithm_provider.clone())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let key = self
            .key_algorithm_provider
            .reconstruct_key(
                key.key_algorithm_type()
                    .ok_or(IssuanceProtocolError::Failed(
                        "Invalid key algorithm".to_string(),
                    ))?,
                &key.public_key,
                None,
                None,
            )
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .public_key_as_jwk()
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_response = self
            .holder_request_credential(
                &interaction_data,
                holder_binding.identifier.did.as_ref().map(|did| &did.did),
                key,
                Some(nonce),
                auth_fn,
                token_response.access_token.expose_secret(),
                wua_proof,
            )
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        let result = self
            .holder_process_accepted_credential(
                credential_response,
                &interaction_data,
                holder_binding,
                storage_access,
                organisation,
                &interaction,
            )
            .await;

        interaction_data.credential_metadata = None;
        interaction_data.notification_id = notification_id.clone();
        storage_access
            .update_interaction(
                interaction.id,
                UpdateInteractionRequest {
                    data: Some(Some(serialize_interaction_data(&interaction_data)?)),
                },
            )
            .await
            .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

        if let (Some(notification_id), Some(notification_endpoint)) =
            (notification_id, interaction_data.notification_endpoint)
        {
            let notification = match &result {
                Ok(_) => OpenID4VCINotificationRequestDTO {
                    notification_id,
                    event: OpenID4VCINotificationEvent::CredentialAccepted,
                    event_description: None,
                },
                Err(err) => OpenID4VCINotificationRequestDTO {
                    notification_id,
                    event: OpenID4VCINotificationEvent::CredentialFailure,
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
        storage_access: &StorageAccess,
    ) -> Result<(), IssuanceProtocolError> {
        let interaction = credential
            .interaction
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
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

        let access_token = self
            .holder_reuse_or_refresh_token(interaction.id, &mut interaction_data, storage_access)
            .await?;

        self.send_notification(
            OpenID4VCINotificationRequestDTO {
                notification_id,
                event: OpenID4VCINotificationEvent::CredentialDeleted,
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
    ) -> Result<ShareResponse<Value>, IssuanceProtocolError> {
        let interaction_id = Uuid::new_v4();

        let mut url = Url::parse(&format!("{}://", self.params.url_scheme))
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let protocol_base_url = self
            .protocol_base_url
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing base_url".to_owned()))?;

        let claims = credential
            .claims
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing claims".to_owned()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let credential_subject = prepare_preview_claims_for_offer(&claims, true)
            .map_err(|e| IssuanceProtocolError::Other(e.into()))?;

        if self.params.credential_offer_by_value {
            let offer = create_credential_offer(
                protocol_base_url,
                &interaction_id.to_string(),
                credential,
                &credential_schema.id,
                &credential_schema.schema_id,
                credential_subject,
            )
            .map_err(|e| IssuanceProtocolError::Other(e.into()))?;

            let offer_string = serde_json::to_string(&offer)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(protocol_base_url.to_owned(), credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }

        Ok(ShareResponse {
            url: query.finish().to_string(),
            interaction_id,
            context: json!(OpenID4VCIIssuerInteractionDataDTO {
                pre_authorized_code_used: false,
                access_token_hash: vec![],
                access_token_expires_at: None,
                refresh_token_hash: None,
                refresh_token_expires_at: None,
                notification_id: None
            }),
        })
    }

    async fn issuer_issue_credential(
        &self,
        credential_id: &CredentialId,
        holder_identifier: Identifier,
        holder_key_id: String,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let Some(mut credential) = self
            .credential_repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        organisation: Some(OrganisationRelations::default()),
                        claim_schemas: Some(ClaimSchemaRelations::default()),
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(DidRelations {
                            keys: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        certificates: Some(CertificateRelations {
                            key: Some(KeyRelations::default()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(CertificateRelations::default()),
                    key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
        else {
            return Err(IssuanceProtocolError::Failed(
                "Credential not found".to_string(),
            ));
        };

        credential.holder_identifier = Some(holder_identifier.clone());

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "credential_schema is None".to_string(),
            ))?
            .clone();
        let credential_state = credential.state;

        let credential_format_type = self
            .config
            .format
            .get_fields(&credential_schema.format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        self.validate_credential_issuable(
            credential_id,
            &credential_state,
            &credential_schema.format,
            credential_format_type,
        )
        .await?;

        let revocation_method = self
            .revocation_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "revocation method not found: {}",
                credential_schema.revocation_method
            )))?;

        let status = revocation_method
            .add_issued_credential(&credential)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_status = status
            .into_iter()
            .map(|revocation_info| revocation_info.credential_status)
            .collect();

        let key = credential
            .key
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("Missing key".to_string()))?;

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "missing issuer identifier".to_string(),
                ))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                key,
                self.jwk_key_id_from_identifier(issuer_identifier, key)?,
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let redirect_uri = credential.redirect_uri.to_owned();

        let core_base_url = self.base_url.as_ref().ok_or(IssuanceProtocolError::Failed(
            "Missing core_base_url for credential issuance".to_string(),
        ))?;

        // TODO - remove organisation usage from here when moved to open core
        let credential_detail = credential_detail_response_from_model(
            credential.clone(),
            &self.config,
            None,
            CredentialAttestationBlobs::default(),
        )
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let additional_contexts = revocation_method
            .get_json_ld_context()
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .url
            .map(|ctx| ctx.parse().map(|ctx| vec![ContextType::Url(ctx)]))
            .transpose()
            .map_err(|_err| {
                IssuanceProtocolError::Failed(
                    "Provided JSON-LD context URL is not a valid URL".to_owned(),
                )
            })?;
        let contexts = vcdm_v2_base_context(additional_contexts);

        let issuer_certificate = if let Some(cert) = credential.issuer_certificate.clone() {
            Some(cert)
        } else {
            credential
                .issuer_identifier
                .as_ref()
                .and_then(|identifier| {
                    identifier
                        .certificates
                        .as_ref()
                        .and_then(|certs| certs.first().cloned())
                })
        };

        let holder_identifier_id = holder_identifier.id;
        let credential_data = credential_data_from_credential_detail_response(
            credential_detail,
            &credential,
            issuer_certificate,
            Some(holder_identifier),
            holder_key_id,
            core_base_url,
            credential_status,
            contexts,
        )
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let token = self
            .formatter_provider
            .get_credential_formatter(&credential_schema.format)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "formatter not found: {}",
                &credential_schema.format
            )))?
            .format_credential(credential_data, auth_fn)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        match (credential_format_type, credential_state) {
            (FormatType::Mdoc, CredentialStateEnum::Accepted) => {
                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
            (FormatType::Mdoc, CredentialStateEnum::Offered) => {
                let credential_blob_id = self.upsert_credential_blob(&credential, &token).await?;

                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(credential_blob_id, holder_identifier_id),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

                self.validity_credential_repository
                    .insert(
                        Mdoc {
                            id: Uuid::new_v4(),
                            created_date: OffsetDateTime::now_utc(),
                            credential: token.as_bytes().to_vec(),
                            linked_credential_id: *credential_id,
                        }
                        .into(),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
            _ => {
                let credential_blob_id = self.upsert_credential_blob(&credential, &token).await?;

                self.credential_repository
                    .update_credential(
                        *credential_id,
                        get_issued_credential_update(credential_blob_id, holder_identifier_id),
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
            }
        }

        Ok(SubmitIssuerResponse {
            credential: token,
            redirect_uri,
            notification_id: Some(generate_alphanumeric(32)),
        })
    }

    async fn holder_continue_issuance(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        storage_access: &StorageAccess,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
        handle_continue_issuance(
            continue_issuance_dto,
            organisation,
            &*self.metadata_cache,
            storage_access,
            self.config_id.to_owned(),
            &*self.key_algorithm_provider,
        )
        .await
    }

    fn get_capabilities(&self) -> IssuanceProtocolCapabilities {
        IssuanceProtocolCapabilities {
            features: vec![Features::SupportsRejection],
            did_methods: vec![
                ConfigDidType::Key,
                ConfigDidType::Jwk,
                ConfigDidType::Web,
                ConfigDidType::WebVh,
            ],
        }
    }
}

#[expect(clippy::too_many_arguments)]
async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &dyn HttpClient,
    fetcher: &dyn OpenIDMetadataFetcher,
    storage_access: &StorageAccess,
    redirect_uri: Option<String>,
    config: &CoreConfig,
    protocol: String,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
    let credential_offer = resolve_credential_offer(client, invitation_url).await?;

    let Metadata {
        token_endpoint,
        issuer_metadata,
        oauth_metadata,
        ..
    } = get_issuer_and_authorization_metadata(
        fetcher,
        &credential_offer.credential_issuer,
        credential_offer.grants.authorization_server(),
    )
    .await?;

    if let OpenID4VCIGrants::AuthorizationCode(authorization_code) = credential_offer.grants {
        let params = config
            .credential_issuer
            .entities
            .iter()
            .filter(|(_, entity)| entity.enabled.unwrap_or(true))
            .filter_map(|(_, entity)| parse_credential_issuer_params(&entity.params).ok())
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
                    .into_iter()
                    .map(
                        |credential_configuration_id| InitiateIssuanceAuthorizationDetailDTO {
                            r#type: "openid_credential".to_string(),
                            credential_configuration_id,
                        },
                    )
                    .collect(),
            ),
            issuer_state: authorization_code.issuer_state,
            authorization_server: authorization_code.authorization_server,
        });
    }

    let tx_code = credential_offer.grants.tx_code().cloned();

    let PrepareIssuanceSuccess {
        interaction_id,
        key_storage_security,
        key_algorithms,
    } = prepare_issuance_interaction(
        organisation,
        token_endpoint,
        issuer_metadata,
        Some(oauth_metadata),
        credential_offer.grants,
        &credential_offer.credential_configuration_ids,
        storage_access,
        None,
        protocol,
        key_algorithm_provider,
    )
    .await?;

    Ok(InvitationResponseEnum::Credential {
        interaction_id,
        tx_code,
        key_storage_security,
        key_algorithms,
    })
}

async fn handle_continue_issuance(
    continue_issuance_dto: ContinueIssuanceDTO,
    organisation: Organisation,
    fetcher: &dyn OpenIDMetadataFetcher,
    storage_access: &StorageAccess,
    protocol: String,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
    let Metadata {
        token_endpoint,
        issuer_metadata,
        oauth_metadata,
        ..
    } = get_issuer_and_authorization_metadata(
        fetcher,
        &continue_issuance_dto.credential_issuer,
        continue_issuance_dto.authorization_server.as_ref(),
    )
    .await?;

    let scope_to_id: HashMap<&String, &String> = issuer_metadata
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

    let PrepareIssuanceSuccess {
        interaction_id,
        key_storage_security,
        key_algorithms,
    } = prepare_issuance_interaction(
        organisation,
        token_endpoint,
        issuer_metadata,
        Some(oauth_metadata),
        OpenID4VCIGrants::AuthorizationCode(OpenID4VCIAuthorizationCodeGrant {
            issuer_state: None, // issuer state was used at the authorization request stage so it is not relevant anymore
            authorization_server: continue_issuance_dto.authorization_server.to_owned(),
        }),
        &all_credential_configuration_ids,
        storage_access,
        Some(continue_issuance_dto),
        protocol,
        key_algorithm_provider,
    )
    .await?;

    Ok(ContinueIssuanceResponseDTO {
        interaction_id,
        key_storage_security_levels: key_storage_security,
        key_algorithms,
    })
}

struct PrepareIssuanceSuccess {
    interaction_id: InteractionId,
    key_storage_security: Option<Vec<KeyStorageSecurity>>,
    key_algorithms: Option<Vec<String>>,
}

#[expect(clippy::too_many_arguments)]
async fn prepare_issuance_interaction(
    organisation: Organisation,
    token_endpoint: String,
    issuer_metadata: OpenID4VCIIssuerMetadataResponseDTO,
    oauth_authorization_server_metadata: Option<OAuthAuthorizationServerMetadataResponseDTO>,
    grants: OpenID4VCIGrants,
    configuration_ids: &[String],
    storage_access: &StorageAccess,
    continue_issuance: Option<ContinueIssuanceDTO>,
    protocol: String,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PrepareIssuanceSuccess, IssuanceProtocolError> {
    // We only support one credential at the time now
    let configuration_id = configuration_ids.first().ok_or_else(|| {
        IssuanceProtocolError::Failed("Credential offer is missing credentials".to_string())
    })?;

    let credential_config = issuer_metadata
        .credential_configurations_supported
        .get(configuration_id)
        .ok_or_else(|| {
            IssuanceProtocolError::Failed(format!(
                "Credential configuration is missing for {configuration_id}"
            ))
        })?;

    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3-2.2
    if let Some(authorization_server) = grants.authorization_server()
        && issuer_metadata
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

    let challenge_endpoint = oauth_authorization_server_metadata
        .as_ref()
        .and_then(|oauth_metadata| oauth_metadata.challenge_endpoint.clone());

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer.clone(),
        credential_endpoint: issuer_metadata.credential_endpoint.clone(),
        notification_endpoint: issuer_metadata.notification_endpoint.to_owned(),
        nonce_endpoint: issuer_metadata.nonce_endpoint.to_owned(),
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
        credential_metadata: credential_config.credential_metadata.clone(),
        credential_configuration_id: configuration_id.to_owned(),
        notification_id: None,
        protocol,
        format: credential_config.format.to_owned(),
    };
    let data = serialize_interaction_data(&holder_data)?;

    let interaction =
        create_and_store_interaction(storage_access, data, Some(organisation)).await?;
    let (key_algorithms, key_storage_security) =
        credential_config_to_holder_signing_algs_and_key_storage_security(
            key_algorithm_provider,
            credential_config,
        );
    Ok(PrepareIssuanceSuccess {
        interaction_id: interaction.id,
        key_storage_security,
        key_algorithms,
    })
}

async fn resolve_credential_offer(
    client: &dyn HttpClient,
    invitation_url: Url,
) -> Result<OpenID4VCIFinal1CredentialOfferDTO, IssuanceProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(IssuanceProtocolError::Failed(format!(
            "Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"
        )));
    }

    if let Some(credential_offer) = credential_offer_param {
        serde_json::from_str(credential_offer).map_err(|error| {
            IssuanceProtocolError::Failed(format!("Failed decoding credential offer {error}"))
        })
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            IssuanceProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        Ok(client
            .get(credential_offer_url.as_str())
            .send()
            .await
            .context("Error during offer request")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error during offer request")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!("Failed decoding credential offer: {error}"))
            })?)
    } else {
        Err(IssuanceProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
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

struct Metadata {
    token_endpoint: String,
    issuer_metadata: OpenID4VCIIssuerMetadataResponseDTO,
    oauth_metadata: OAuthAuthorizationServerMetadataResponseDTO,
}

async fn get_issuer_and_authorization_metadata(
    fetcher: &dyn OpenIDMetadataFetcher,
    credential_issuer: &str,
    authorization_server: Option<&String>,
) -> Result<Metadata, IssuanceProtocolError> {
    let credential_issuer_endpoint: Url = credential_issuer.parse().map_err(|_| {
        IssuanceProtocolError::InvalidRequest(format!(
            "Invalid credential issuer url {credential_issuer}",
        ))
    })?;

    let issuer_metadata_endpoint =
        prepend_well_known_path(&credential_issuer_endpoint, "openid-credential-issuer");

    let issuer_metadata: OpenID4VCIIssuerMetadataResponseDTO = fetcher
        .fetch(&issuer_metadata_endpoint)
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

    let authorization_server = if let Some(authorization_server) = authorization_server {
        if issuer_metadata
            .authorization_servers
            .as_ref()
            .is_none_or(|servers| !servers.contains(authorization_server))
        {
            return Err(IssuanceProtocolError::InvalidRequest(format!(
                "Authorization server missing in issuer metadata: {authorization_server}"
            )));
        }

        authorization_server.to_owned()
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

    let authorization_server_endpoint: Url = authorization_server.parse().map_err(|_| {
        IssuanceProtocolError::InvalidRequest(format!(
            "Invalid authorization_server url {authorization_server}",
        ))
    })?;

    let authorization_server_metadata_endpoint =
        prepend_well_known_path(&authorization_server_endpoint, "oauth-authorization-server");

    let oauth_metadata_response: OAuthAuthorizationServerMetadata = fetcher
        .fetch(&authorization_server_metadata_endpoint)
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

    let token_endpoint = oauth_metadata_response
        .token_endpoint
        .as_ref()
        .ok_or(IssuanceProtocolError::Failed(
            "Missing token_endpoint".to_string(),
        ))?
        .to_string();

    Ok(Metadata {
        token_endpoint,
        issuer_metadata,
        oauth_metadata: oauth_metadata_response.into(),
    })
}

async fn create_and_store_interaction(
    storage_access: &StorageAccess,
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, IssuanceProtocolError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(Some(data), now, organisation);

    storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(IssuanceProtocolError::StorageAccessError)?;

    Ok(interaction)
}

struct IdentifierUpdates {
    issuer_identifier_id: IdentifierId,
    issuer_certificate_id: Option<CertificateId>,
    create_did: Option<Did>,
    create_identifier: Option<Identifier>,
    create_certificate: Option<Certificate>,
    create_key: Option<Key>,
}

async fn prepare_did_identifier(
    issuer_did_value: DidValue,
    organisation: &Organisation,
    storage_access: &StorageAccess,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    match storage_access
        .get_did_by_value(&issuer_did_value, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?
    {
        Some(did) => {
            let identifier = storage_access
                .get_identifier_for_did(&did.id)
                .await
                .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

            Ok(IdentifierUpdates {
                issuer_identifier_id: identifier.id,
                issuer_certificate_id: None,
                create_did: None,
                create_identifier: None,
                create_certificate: None,
                create_key: None,
            })
        }
        None => {
            let now = OffsetDateTime::now_utc();
            let did_method = did_method_provider
                .get_did_method_id(&issuer_did_value)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "unsupported issuer did method: {issuer_did_value}"
                )))?;
            let id = Uuid::new_v4().into();
            let did = Did {
                id,
                name: format!("issuer {id}"),
                created_date: now,
                last_modified: now,
                did: issuer_did_value,
                did_type: DidType::Remote,
                did_method,
                keys: None,
                deactivated: false,
                organisation: Some(organisation.clone()),
                log: None,
            };

            let id: IdentifierId = Uuid::new_v4().into();
            Ok(IdentifierUpdates {
                issuer_identifier_id: id,
                issuer_certificate_id: None,
                create_did: Some(did.to_owned()),
                create_identifier: Some(Identifier {
                    id,
                    name: did.name.to_owned(),
                    created_date: now,
                    last_modified: now,
                    did: Some(did),
                    key: None,
                    certificates: None,
                    is_remote: true,
                    deleted_at: None,
                    r#type: IdentifierType::Did,
                    state: IdentifierState::Active,
                    organisation: Some(organisation.clone()),
                }),
                create_certificate: None,
                create_key: None,
            })
        }
    }
}

async fn prepare_certificate_identifier(
    certificate: Option<Certificate>,
    organisation: &Organisation,
    storage_access: &StorageAccess,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    let certificate = certificate.ok_or(IssuanceProtocolError::Failed(
        "Missing issuer certificate".to_string(),
    ))?;

    match storage_access
        .get_certificate_by_fingerprint(&certificate.fingerprint, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?
    {
        Some(certificate) => Ok(IdentifierUpdates {
            issuer_identifier_id: certificate.identifier_id,
            issuer_certificate_id: Some(certificate.id),
            create_did: None,
            create_identifier: None,
            create_certificate: None,
            create_key: None,
        }),

        None => {
            let now = OffsetDateTime::now_utc();
            let identifier_id: IdentifierId = Uuid::new_v4().into();
            let certificate = Certificate {
                identifier_id,
                organisation_id: Some(organisation.id),
                ..certificate
            };

            Ok(IdentifierUpdates {
                issuer_identifier_id: identifier_id,
                issuer_certificate_id: Some(certificate.id),
                create_did: None,
                create_identifier: Some(Identifier {
                    id: identifier_id,
                    name: format!("issuer {identifier_id}"),
                    created_date: now,
                    last_modified: now,
                    did: None,
                    key: None,
                    certificates: None,
                    is_remote: true,
                    deleted_at: None,
                    r#type: IdentifierType::Certificate,
                    state: IdentifierState::Active,
                    organisation: Some(organisation.clone()),
                }),
                create_certificate: Some(certificate),
                create_key: None,
            })
        }
    }
}

async fn prepare_key_identifier(
    key: Key,
    organisation: &Organisation,
    storage_access: &StorageAccess,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    let now = OffsetDateTime::now_utc();
    let algorithm_type = KeyAlgorithmType::from_str(&key.key_type)
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    let stored_key = storage_access
        .get_key_by_raw_key_and_type(key.public_key.to_owned(), algorithm_type, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    let (key, create_key) = if let Some(key) = stored_key {
        (key, None)
    } else {
        let key = Key {
            organisation: Some(organisation.clone()),
            storage_type: "INTERNAL".to_string(),
            ..key
        };
        (key.clone(), Some(key))
    };

    let identifier = storage_access
        .get_identifier_for_key(key.id, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    if let Some(identifier) = identifier {
        Ok(IdentifierUpdates {
            issuer_identifier_id: identifier.id,
            issuer_certificate_id: None,
            create_did: None,
            create_identifier: None,
            create_certificate: None,
            create_key,
        })
    } else {
        let identifier_id = Uuid::new_v4().into();
        Ok(IdentifierUpdates {
            issuer_identifier_id: identifier_id,
            issuer_certificate_id: None,
            create_did: None,
            create_identifier: Some(Identifier {
                id: identifier_id,
                created_date: now,
                last_modified: now,
                name: format!("Issuer {identifier_id}"),
                r#type: IdentifierType::Key,
                is_remote: true,
                state: IdentifierState::Active,
                deleted_at: None,
                organisation: Some(organisation.clone()),
                did: None,
                key: Some(key.clone()),
                certificates: None,
            }),
            create_certificate: None,
            create_key,
        })
    }
}

#[derive(Debug, Default)]
struct CredentialSchemaUpdates {
    update: Option<UpdateCredentialSchemaRequest>,
    create: Option<CredentialSchema>,
}

async fn prepare_credential_schema(
    credential_schema: CredentialSchema,
    organisation: &Organisation,
    storage_access: &StorageAccess,
    credential: &mut Credential,
) -> Result<CredentialSchemaUpdates, IssuanceProtocolError> {
    let stored_schema = storage_access
        .get_schema(&credential_schema.schema_id, organisation.id)
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    if let Some(stored_schema) = stored_schema {
        let claims = credential
            .claims
            .as_mut()
            .ok_or(IssuanceProtocolError::Failed("Missing claims".to_string()))?;

        let stored_claim_schemas =
            stored_schema
                .claim_schemas
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing claim_schemas".to_string(),
                ))?;

        let parsed_claim_schemas =
            credential_schema
                .claim_schemas
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing claim_schemas".to_string(),
                ))?;

        let mut new_claim_schemas = vec![];
        for parsed_claim_schema in parsed_claim_schemas {
            let stored_claim_schema = stored_claim_schemas
                .iter()
                .find(|schema| schema.schema.key == parsed_claim_schema.schema.key);

            if let Some(stored_claim_schema) = stored_claim_schema {
                // link all matching credential claims to the stored claim_schema
                claims
                    .iter_mut()
                    .filter(|claim| {
                        claim
                            .schema
                            .as_ref()
                            .is_some_and(|schema| schema.id == parsed_claim_schema.schema.id)
                    })
                    .for_each(|claim| {
                        claim.schema = Some(stored_claim_schema.schema.to_owned());
                    });
            } else {
                new_claim_schemas.push(parsed_claim_schema);
            }
        }

        let id = stored_schema.id;
        credential.schema = Some(stored_schema);

        if new_claim_schemas.is_empty() {
            return Ok(Default::default());
        }

        Ok(CredentialSchemaUpdates {
            update: Some(UpdateCredentialSchemaRequest {
                id,
                revocation_method: None,
                format: None,
                claim_schemas: Some(new_claim_schemas),
                layout_type: None,
                layout_properties: None,
            }),
            create: None,
        })
    } else {
        Ok(CredentialSchemaUpdates {
            update: None,
            create: Some(credential_schema),
        })
    }
}

async fn create_wallet_unit_attestation_pop(
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key: &Key,
    audience: &str,
    challenge: Option<String>,
) -> Result<String, IssuanceProtocolError> {
    #[derive(Serialize)]
    struct WalletUnitPopCustomClaims {
        #[serde(skip_serializing_if = "Option::is_none")]
        challenge: Option<String>,
    }

    let now = OffsetDateTime::now_utc();

    let attestation_auth_fn = key_provider
        .get_attestation_signature_provider(key, None, key_algorithm_provider.clone())
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

    let auth_fn = key_provider
        .get_signature_provider(key, None, key_algorithm_provider)
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

    let proof = Jwt::new(
        "oauth-client-attestation-pop+jwt".to_string(),
        auth_fn.jose_alg().ok_or(IssuanceProtocolError::Failed(
            "No JOSE alg specified".to_string(),
        ))?,
        auth_fn.get_key_id(),
        None,
        JWTPayload {
            issued_at: Some(now),
            expires_at: Some(now + Duration::minutes(60)),
            invalid_before: Some(now),
            audience: Some(vec![audience.to_string()]),
            jwt_id: Some(Uuid::new_v4().to_string()),
            issuer: None,
            subject: None,
            proof_of_possession_key: None,
            custom: WalletUnitPopCustomClaims { challenge },
        },
    );

    // We first attempt to sign with the attestation auth fn
    // If that fails, we fall back to the auth fn
    // To be fixed in https://procivis.atlassian.net/browse/ONE-7501
    let signed_proof = proof.tokenize(Some(&*attestation_auth_fn)).await;

    match signed_proof {
        Ok(signed_proof) => Ok(signed_proof),
        Err(_) => proof
            .tokenize(Some(&*auth_fn))
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string())),
    }
}
