//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::utilities::generate_alphanumeric;
use secrecy::{ExposeSecret, SecretString};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use shared_types::{BlobId, CertificateId, CredentialId, DidValue, IdentifierId};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::{ContinueIssuanceDTO, Features, IssuanceProtocolCapabilities};
use super::error::TxCodeError;
use super::mapper::{get_issued_credential_update, interaction_from_handle_invitation};
use super::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, ShareResponse, SubmitIssuerResponse,
    UpdateResponse,
};
use super::openid4vci_final1_0::mapper::{
    get_credential_offer_url, parse_credential_issuer_params,
};
use super::openid4vci_final1_0::model::{
    ChallengeResponseDTO, HolderInteractionData, OpenID4VCIAuthorizationCodeGrant,
    OpenID4VCICredentialRequestDTO, OpenID4VCIDiscoveryResponseDTO, OpenID4VCIFinal1Params,
    OpenID4VCIGrants, OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINonceResponseDTO, OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use super::openid4vci_final1_0::proof_formatter::OpenID4VCIProofJWTFormatter;
use super::openid4vci_final1_0::service::{create_credential_offer, get_protocol_base_url};
use super::{
    IssuanceProtocol, IssuanceProtocolError, StorageAccess, deserialize_interaction_data,
    serialize_interaction_data,
};
use crate::config::core_config::{
    CoreConfig, DidType as ConfigDidType, KeyAlgorithmType, RevocationType,
};
use crate::mapper::oidc::map_from_oidc_format_to_core_detailed;
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialStateEnum};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType, LayoutType,
    UpdateCredentialSchemaRequest, WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidRelations, DidType, KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionId, UpdateInteractionRequest};
use crate::model::key::{Key, KeyRelations, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::revocation_list::{
    RevocationListPurpose, StatusListCredentialFormat, StatusListType,
};
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::model::wallet_unit_attestation::WalletUnitAttestationRelations;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::JWTPayload;
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::{
    OpenID4VCICredentialRequestIdentifier, OpenID4VCICredentialRequestProofs,
    OpenID4VCIFinal1CredentialOfferDTO,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::model::CredentialAdditionalData;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::revocation::{RevocationMethod, token_status_list};
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::revocation_list_repository::RevocationListRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::repository::wallet_unit_attestation_repository::WalletUnitAttestationRepository;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::MissingProviderError;
use crate::service::oid4vci_final1_0::dto::{
    OAuthAuthorizationServerMetadataResponseDTO, OpenID4VCICredentialResponseDTO,
};
use crate::service::oid4vci_final1_0::service::prepare_preview_claims_for_offer;
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;
use crate::util::params::convert_params;
use crate::util::revocation_update::{get_or_create_revocation_list_id, process_update};
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;
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
    credential_repository: Arc<dyn CredentialRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
    revocation_list_repository: Arc<dyn RevocationListRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    protocol_base_url: Option<String>,
    config: Arc<CoreConfig>,
    params: OpenID4VCIFinal1Params,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    config_id: String,
}

impl OpenID4VCIFinal1_0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        revocation_list_repository: Arc<dyn RevocationListRepository>,
        wallet_unit_attestation_repository: Arc<dyn WalletUnitAttestationRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIFinal1Params,
        config_id: String,
    ) -> Self {
        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            client,
            credential_repository,
            validity_credential_repository,
            revocation_list_repository,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            wallet_unit_attestation_repository,
            key_algorithm_provider,
            key_provider,
            base_url,
            protocol_base_url,
            config,
            params,
            blob_storage_provider,
            config_id,
        }
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        credential_schema: &CredentialSchema,
    ) -> Result<(), IssuanceProtocolError> {
        match (latest_state, &credential_schema.schema_type) {
            (CredentialStateEnum::Accepted, CredentialSchemaType::Mdoc) => {
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
                    + self.mso_minimum_refresh_time(&credential_schema.format)?;

                if can_be_updated_at > OffsetDateTime::now_utc() {
                    return Err(IssuanceProtocolError::RefreshTooSoon);
                }
            }
            (CredentialStateEnum::Suspended, CredentialSchemaType::Mdoc) => {
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

    fn mso_minimum_refresh_time(&self, format: &str) -> Result<Duration, IssuanceProtocolError> {
        self.config
            .format
            .get::<mdoc_formatter::Params>(format)
            .map(|p| p.mso_minimum_refresh_time)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))
    }

    async fn prepare_issuer_revocation_data(
        &self,
        credential: &mut Credential,
        credential_schema: &CredentialSchema,
        revocation_method: &Arc<dyn RevocationMethod>,
    ) -> Result<Option<CredentialAdditionalData>, IssuanceProtocolError> {
        let revocation_type = self
            .config
            .revocation
            .get_fields(&credential_schema.revocation_method)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        match revocation_type {
            RevocationType::None
            | RevocationType::MdocMsoUpdateSuspension
            | RevocationType::Lvvc => return Ok(None),
            RevocationType::BitstringStatusList | RevocationType::TokenStatusList => {
                // continue processing
            }
        };

        let issuer_identifier =
            credential
                .issuer_identifier
                .as_ref()
                .cloned()
                .ok_or(IssuanceProtocolError::Failed(
                    "issuer_identifier is None".to_string(),
                ))?;

        let credentials_by_issuer_identifier = self
            .credential_repository
            .get_credentials_by_issuer_identifier_id(
                issuer_identifier.id,
                &CredentialRelations::default(),
            )
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let credential_data = if revocation_type == RevocationType::BitstringStatusList {
            let crate::provider::revocation::bitstring_status_list::Params { format } =
                convert_params(
                    revocation_method
                        .get_params()
                        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                )
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

            let status_list_format = if format == StatusListCredentialFormat::JsonLdClassic
                && credential_schema.format == "JSON_LD_BBSPLUS"
            {
                "JSON_LD_BBSPLUS".to_string()
            } else {
                format.to_string()
            };

            let formatter = self
                .formatter_provider
                .get_credential_formatter(&status_list_format)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "formatter not found: {status_list_format}"
                )))?;

            Some(CredentialAdditionalData {
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_identifier,
                    issuer_identifier.clone(),
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &*self.key_provider,
                    &self.key_algorithm_provider,
                    &self.base_url,
                    &*formatter,
                    &StatusListType::BitstringStatusList,
                    &format,
                )
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                suspension_list_id: Some(
                    get_or_create_revocation_list_id(
                        &credentials_by_issuer_identifier,
                        issuer_identifier,
                        RevocationListPurpose::Suspension,
                        &*self.revocation_list_repository,
                        &*self.key_provider,
                        &self.key_algorithm_provider,
                        &self.base_url,
                        &*formatter,
                        &StatusListType::BitstringStatusList,
                        &format,
                    )
                    .await
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                ),
                credentials_by_issuer_identifier,
            })
        } else if revocation_type == RevocationType::TokenStatusList {
            let token_status_list::Params { format } = convert_params(
                revocation_method
                    .get_params()
                    .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
            )
            .unwrap_or_default();

            let formatter = self
                .formatter_provider
                .get_credential_formatter(&format.to_string())
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "formatter not found: {format}"
                )))?;

            Some(CredentialAdditionalData {
                revocation_list_id: get_or_create_revocation_list_id(
                    &credentials_by_issuer_identifier,
                    issuer_identifier,
                    RevocationListPurpose::Revocation,
                    &*self.revocation_list_repository,
                    &*self.key_provider,
                    &self.key_algorithm_provider,
                    &self.base_url,
                    &*formatter,
                    &StatusListType::TokenStatusList,
                    &format,
                )
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?,
                suspension_list_id: None,
                credentials_by_issuer_identifier,
            })
        } else {
            None
        };

        Ok(credential_data)
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
        client_attestation: Option<&str>,
        client_attestation_pop: Option<&str>,
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

        if let (Some(client_attestation), Some(client_attestation_pop)) =
            (client_attestation, client_attestation_pop)
        {
            request = request
                .header("OAuth-Client-Attestation", client_attestation)
                .header("OAuth-Client-Attestation-PoP", client_attestation_pop);
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
                    ..Default::default()
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
        storage_access: &StorageAccess,
        organisation: &Organisation,
        interaction: &Interaction,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        let format = map_from_oidc_format_to_core_detailed(
            &interaction_data.format,
            Some(&issuer_response.credential),
        )
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&format)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{format} formatter not found"))
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
        schema.wallet_storage_type =
            metadata.and_then(|metadata| metadata.wallet_storage_type.to_owned());

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

    #[allow(clippy::too_many_arguments)]
    async fn holder_request_credential(
        &self,
        interaction_data: &HolderInteractionData,
        holder_did: &DidValue,
        holder_key: PublicKeyJwk,
        nonce: Option<String>,
        auth_fn: AuthenticationFn,
        access_token: &str,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        // Very basic support for JWK as crypto binding method for EUDI
        let jwk = match interaction_data
            .cryptographic_binding_methods_supported
            .to_owned()
        {
            Some(methods) => {
                // Prefer kid-based holder binding proofs instead of using jwk because
                // that way the did does not need to be resolved.
                if methods
                    .iter()
                    .any(|method| &format!("did:{}", holder_did.method()) == method)
                    // swiyu specific workaround: in the swiyu configuration did:jwk is specified, but jwk is expected instead
                    && methods != vec!["did:jwk".to_string()]
                {
                    None
                } else if methods.contains(&"jwk".to_string())
                    // swiyu specific workaround
                    || methods == vec!["did:jwk".to_string()]
                {
                    Some(holder_key.into())
                } else {
                    None
                }
            }
            None => None,
        };

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url.to_owned(),
            jwk,
            nonce,
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
}

#[async_trait]
impl IssuanceProtocol for OpenID4VCIFinal1_0 {
    fn holder_can_handle(&self, url: &Url) -> bool {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        self.params.url_scheme == url.scheme()
            && (query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
                || query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY))
    }

    async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        redirect_uri: Option<String>,
    ) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
        if !self.holder_can_handle(&url) {
            return Err(IssuanceProtocolError::Failed(
                "No OpenID4VC query params detected".to_string(),
            ));
        }

        handle_credential_invitation(
            url,
            organisation,
            &*self.client,
            storage_access,
            redirect_uri,
            &self.config,
            self.config_id.to_owned(),
        )
        .await
    }

    async fn holder_accept_credential(
        &self,
        interaction: Interaction,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        let organisation =
            interaction
                .organisation
                .as_ref()
                .ok_or(IssuanceProtocolError::Failed(
                    "organisation is None".to_string(),
                ))?;

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let (wallet_attestation, wallet_attestation_pop) = if interaction_data
            .token_endpoint_auth_methods_supported
            .as_ref()
            .unwrap_or(&vec![])
            .contains(&"attest_jwt_client_auth".to_string())
        {
            let wallet_unit_attestation = self
                .wallet_unit_attestation_repository
                .get_wallet_unit_attestation_by_organisation(
                    &organisation.id,
                    &WalletUnitAttestationRelations {
                        key: Some(KeyRelations::default()),
                        ..Default::default()
                    },
                )
                .await
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

            let wua_key = wallet_unit_attestation
                .as_ref()
                .and_then(|wua| wua.key.clone())
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing Wallet Unit key".to_string(),
                ))?;

            // Fetch challenge if challenge_endpoint is present
            let challenge = if let Some(challenge_endpoint) = &interaction_data.challenge_endpoint {
                Some(self.holder_fetch_challenge(challenge_endpoint).await?)
            } else {
                None
            };

            let signed_proof = create_wallet_unit_attestation_pop(
                &*self.key_provider,
                self.key_algorithm_provider.clone(),
                &wua_key,
                &interaction_data.issuer_url,
                challenge,
            )
            .await?;

            (wallet_unit_attestation, Some(signed_proof))
        } else {
            (None, None)
        };

        let token_response = self
            .holder_fetch_token(
                &interaction_data,
                tx_code,
                wallet_attestation
                    .as_ref()
                    .map(|wua| wua.attestation.as_str()),
                wallet_attestation_pop.as_deref(),
            )
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

        let auth_fn = self
            .key_provider
            .get_signature_provider(key, jwk_key_id.clone(), self.key_algorithm_provider.clone())
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
                &holder_did.did,
                key,
                Some(nonce),
                auth_fn,
                token_response.access_token.expose_secret(),
            )
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        let result = self
            .holder_process_accepted_credential(
                credential_response,
                &interaction_data,
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
                    ..Default::default()
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

        self.validate_credential_issuable(credential_id, &credential_state, &credential_schema)
            .await?;

        let format = credential_schema.format.to_owned();

        let revocation_method = self
            .revocation_provider
            .get_revocation_method(&credential_schema.revocation_method)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "revocation method not found: {}",
                credential_schema.revocation_method
            )))?;

        let credential_additional_data = self
            .prepare_issuer_revocation_data(&mut credential, &credential_schema, &revocation_method)
            .await?;

        let (update, status) = revocation_method
            .add_issued_credential(&credential, credential_additional_data)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        if let Some(update) = update {
            process_update(
                update,
                &*self.validity_credential_repository,
                &*self.revocation_list_repository,
            )
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        }

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
        let credential_detail =
            credential_detail_response_from_model(credential.clone(), &self.config, None, None)
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
            .get_credential_formatter(&format)
            .ok_or(IssuanceProtocolError::Failed(format!(
                "formatter not found: {format}"
            )))?
            .format_credential(credential_data, auth_fn)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        match (credential_schema.schema_type, credential_state) {
            (CredentialSchemaType::Mdoc, CredentialStateEnum::Accepted) => {
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
            (CredentialSchemaType::Mdoc, CredentialStateEnum::Offered) => {
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
            &*self.client,
            storage_access,
            self.config_id.to_owned(),
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

#[allow(clippy::too_many_arguments)]
async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &dyn HttpClient,
    storage_access: &StorageAccess,
    redirect_uri: Option<String>,
    config: &CoreConfig,
    protocol: String,
) -> Result<InvitationResponseEnum, IssuanceProtocolError> {
    let credential_offer = resolve_credential_offer(client, invitation_url).await?;

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

        // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html#section-11.2.3-2.2
        if let Some(authorization_server) = &authorization_code.authorization_server {
            let credential_issuer_endpoint: Url = params.issuer.parse().map_err(|_| {
                IssuanceProtocolError::InvalidRequest(format!(
                    "Invalid credential issuer url {}",
                    params.issuer
                ))
            })?;

            let (_, issuer_metadata, _) =
                get_discovery_and_issuer_metadata(client, &credential_issuer_endpoint).await?;

            if issuer_metadata
                .authorization_servers
                .is_none_or(|servers| !servers.contains(authorization_server))
            {
                return Err(IssuanceProtocolError::InvalidRequest(format!(
                    "Authorization server missing in issuer metadata: {authorization_server}"
                )));
            }
        }

        return Ok(InvitationResponseEnum::AuthorizationFlow {
            organisation_id: organisation.id,
            issuer: params.issuer,
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

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (token_endpoint, issuer_metadata, auth_server_metadata) =
        get_discovery_and_issuer_metadata(client, &credential_issuer_endpoint).await?;

    let (interaction_id, wallet_storage_type) = prepare_issuance_interaction(
        organisation,
        token_endpoint,
        issuer_metadata,
        auth_server_metadata,
        credential_offer.grants,
        &credential_offer.credential_configuration_ids,
        storage_access,
        None,
        protocol,
    )
    .await?;

    Ok(InvitationResponseEnum::Credential {
        interaction_id,
        tx_code,
        wallet_storage_type,
    })
}

async fn handle_continue_issuance(
    continue_issuance_dto: ContinueIssuanceDTO,
    organisation: Organisation,
    client: &dyn HttpClient,
    storage_access: &StorageAccess,
    protocol: String,
) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
    let credential_issuer_endpoint: Url =
        continue_issuance_dto
            .credential_issuer
            .parse()
            .map_err(|_| {
                IssuanceProtocolError::Failed(format!(
                    "Invalid credential issuer url {}",
                    continue_issuance_dto.credential_issuer
                ))
            })?;

    let (token_endpoint, issuer_metadata, auth_server_metadata) =
        get_discovery_and_issuer_metadata(client, &credential_issuer_endpoint).await?;

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

    let (interaction_id, wallet_storage_type) = prepare_issuance_interaction(
        organisation,
        token_endpoint,
        issuer_metadata,
        auth_server_metadata,
        OpenID4VCIGrants::AuthorizationCode(OpenID4VCIAuthorizationCodeGrant {
            issuer_state: None, // issuer state was used at the authorization request stage so it is not relevant anymore
            authorization_server: continue_issuance_dto.authorization_server.to_owned(),
        }),
        &all_credential_configuration_ids,
        storage_access,
        Some(continue_issuance_dto),
        protocol,
    )
    .await?;

    Ok(ContinueIssuanceResponseDTO {
        interaction_id,
        wallet_storage_type,
    })
}

#[allow(clippy::too_many_arguments)]
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
) -> Result<(InteractionId, Option<WalletStorageTypeEnum>), IssuanceProtocolError> {
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
    Ok((
        interaction.id,
        credential_config
            .credential_metadata
            .as_ref()
            .and_then(|cm| cm.wallet_storage_type),
    ))
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
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .map_err(|error| {
                IssuanceProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?)
    } else {
        Err(IssuanceProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

async fn get_discovery_and_issuer_metadata(
    client: &dyn HttpClient,
    credential_issuer_endpoint: &Url,
) -> Result<
    (
        String,
        OpenID4VCIIssuerMetadataResponseDTO,
        Option<OAuthAuthorizationServerMetadataResponseDTO>,
    ),
    IssuanceProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &dyn HttpClient,
        endpoint: String,
    ) -> Result<T, IssuanceProtocolError> {
        client
            .get(&endpoint)
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(IssuanceProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)
    }

    let prepend_well_known_path = |well_known_path_segment: &str| -> String {
        let origin = {
            let mut url = credential_issuer_endpoint.clone();
            url.set_path("");
            url.to_string()
        };
        let path = match credential_issuer_endpoint.path() {
            "/" => "", // do not append trailing slash for empty path
            path => path,
        };
        format!("{origin}.well-known/{well_known_path_segment}{path}")
    };

    let oauth_authorization_server_metadata_future = async {
        let oauth_authorization_server_metadata_endpoint =
            prepend_well_known_path("oauth-authorization-server");

        let response: Result<OAuthAuthorizationServerMetadataResponseDTO, IssuanceProtocolError> =
            client
                .get(&oauth_authorization_server_metadata_endpoint)
                .send()
                .await
                .context("send error")
                .map_err(IssuanceProtocolError::Transport)
                .and_then(|response| {
                    response
                        .error_for_status()
                        .context("status error")
                        .map_err(IssuanceProtocolError::Transport)
                        .and_then(|response| {
                            response
                                .json()
                                .context("parsing error")
                                .map_err(IssuanceProtocolError::Transport)
                        })
                });

        match response {
            Ok(response) => Ok(Some(response)),
            Err(error) => {
                tracing::warn!("Failed to fetch OAuth authorization server metadata: {error}");
                Ok(None)
            }
        }
    };

    let token_endpoint_future = async {
        let openid_configuration_endpoint = prepend_well_known_path("openid-configuration");

        let response = client
            .get(&openid_configuration_endpoint)
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;

        if response.status.0 == 404 {
            // Fallback for https://datatracker.ietf.org/doc/html/rfc8414#section-3,
            // since there is no specification where to obtain the token endpoint
            // if the issuer is not providing .well-known/openid-configuration
            Ok(format!("{credential_issuer_endpoint}/token"))
        } else {
            let oidc_discovery: OpenID4VCIDiscoveryResponseDTO = response
                .error_for_status()
                .context("status error")
                .map_err(IssuanceProtocolError::Transport)?
                .json()
                .context("parsing error")
                .map_err(IssuanceProtocolError::Transport)?;
            Ok(oidc_discovery.token_endpoint)
        }
    };

    let issuer_metadata_endpoint = prepend_well_known_path("openid-credential-issuer");

    let issuer_metadata = fetch(client, issuer_metadata_endpoint);
    tokio::try_join!(
        token_endpoint_future,
        issuer_metadata,
        oauth_authorization_server_metadata_future
    )
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
        .get_schema(
            &credential_schema.schema_id,
            &credential_schema.schema_type.to_string(),
            organisation.id,
        )
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    if let Some(stored_schema) = stored_schema {
        let claims = credential
            .claims
            .as_mut()
            .ok_or(IssuanceProtocolError::Failed("Missing claims".to_string()))?;

        let stored_claim_schemas = stored_schema
            .claim_schemas
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing claim_schemas".to_string(),
            ))?
            .to_owned();
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

        let all_claim_schemas = [&stored_claim_schemas[..], &new_claim_schemas[..]].concat();

        Ok(CredentialSchemaUpdates {
            update: Some(UpdateCredentialSchemaRequest {
                id,
                revocation_method: None,
                format: None,
                claim_schemas: Some(all_claim_schemas),
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
    let signed_proof = proof.tokenize(Some(attestation_auth_fn)).await;

    match signed_proof {
        Ok(signed_proof) => Ok(signed_proof),
        Err(_) => proof
            .tokenize(Some(auth_fn))
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string())),
    }
}
