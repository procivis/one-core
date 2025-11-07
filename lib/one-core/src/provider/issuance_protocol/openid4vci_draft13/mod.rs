//! Implementation of OpenID4VCI.
//! https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-ID1.html

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use indexmap::IndexMap;
use one_crypto::encryption::{decrypt_string, encrypt_string};
use one_crypto::utilities::generate_alphanumeric;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use shared_types::{
    BlobId, CertificateId, CredentialId, DidValue, HolderWalletUnitId, IdentifierId,
};
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use super::dto::{ContinueIssuanceDTO, IssuanceProtocolCapabilities};
use super::{BasicSchemaData, IssuanceProtocol, IssuanceProtocolError, StorageAccess};
use crate::config::core_config::{
    CoreConfig, DidType as ConfigDidType, FormatType, IssuanceProtocolType,
};
use crate::mapper::oidc::{map_from_oidc_format_to_core_detailed, map_to_openid4vp_format};
use crate::mapper::{IdentifierRole, NESTED_CLAIM_MARKER, RemoteIdentifierRelation};
use crate::model::blob::{Blob, BlobType, UpdateBlobRequest};
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Clearable, Credential, CredentialRelations, CredentialStateEnum, UpdateCredentialRequest,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, UpdateCredentialSchemaRequest,
    WalletStorageTypeEnum,
};
use crate::model::did::{Did, DidRelations, DidType, KeyFilter, KeyRole};
use crate::model::identifier::{Identifier, IdentifierRelations, IdentifierState, IdentifierType};
use crate::model::interaction::{Interaction, InteractionId, UpdateInteractionRequest};
use crate::model::key::{Key, KeyRelations, PublicKeyJwk};
use crate::model::organisation::{Organisation, OrganisationRelations};
use crate::model::validity_credential::{Mdoc, ValidityCredentialType};
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::key_verification::KeyVerification;
use crate::provider::blob_storage_provider::{BlobStorageProvider, BlobStorageType};
use crate::provider::credential_formatter::mapper::credential_data_from_credential_detail_response;
use crate::provider::credential_formatter::mdoc_formatter;
use crate::provider::credential_formatter::model::{
    AuthenticationFn, CertificateDetails, IdentifierDetails,
};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::credential_formatter::vcdm::ContextType;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::issuance_protocol::dto::Features;
use crate::provider::issuance_protocol::error::TxCodeError;
use crate::provider::issuance_protocol::mapper::{
    get_issued_credential_update, interaction_from_handle_invitation,
};
use crate::provider::issuance_protocol::model::{
    ContinueIssuanceResponseDTO, InvitationResponseEnum, ShareResponse, SubmitIssuerResponse,
    UpdateResponse,
};
use crate::provider::issuance_protocol::openid4vci_draft13::handle_invitation_operations::{
    HandleInvitationOperations, HandleInvitationOperationsAccess,
};
use crate::provider::issuance_protocol::openid4vci_draft13::mapper::{
    create_credential, extract_offered_claims, get_credential_offer_url,
    parse_credential_issuer_params,
};
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    ExtendedSubjectDTO, HolderInteractionData, OAuthAuthorizationServerMetadata,
    OpenID4VCIAuthorizationCodeGrant, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferDTO,
    OpenID4VCICredentialRequestDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDraft13Params, OpenID4VCIGrants,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO,
    OpenID4VCINotificationEvent, OpenID4VCINotificationRequestDTO, OpenID4VCIProofRequestDTO,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO,
};
use crate::provider::issuance_protocol::openid4vci_draft13::proof_formatter::OpenID4VCIProofJWTFormatter;
use crate::provider::issuance_protocol::openid4vci_draft13::service::{
    create_credential_offer, get_protocol_base_url,
};
use crate::provider::issuance_protocol::openid4vci_draft13::validator::validate_issuer;
use crate::provider::issuance_protocol::{
    BuildCredentialSchemaResponse, deserialize_interaction_data, serialize_interaction_data,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::validity_credential_repository::ValidityCredentialRepository;
use crate::service::certificate::dto::CertificateX509AttributesDTO;
use crate::service::credential::mapper::credential_detail_response_from_model;
use crate::service::error::MissingProviderError;
use crate::service::oid4vci_draft13::service::credentials_format;
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;
use crate::util::vcdm_jsonld_contexts::vcdm_v2_base_context;
use crate::validator::{validate_expiration_time, validate_issuance_time};

pub mod handle_invitation_operations;
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

pub(crate) struct OpenID4VCI13 {
    client: Arc<dyn HttpClient>,
    credential_repository: Arc<dyn CredentialRepository>,
    validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    base_url: Option<String>,
    protocol_base_url: Option<String>,
    config: Arc<CoreConfig>,
    params: OpenID4VCIDraft13Params,
    blob_storage_provider: Arc<dyn BlobStorageProvider>,
    handle_invitation_operations: Arc<dyn HandleInvitationOperations>,
}

impl OpenID4VCI13 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIDraft13Params,
        handle_invitation_operations: Arc<dyn HandleInvitationOperations>,
    ) -> Self {
        let protocol_base_url = base_url.as_ref().map(|url| get_protocol_base_url(url));
        Self {
            client,
            credential_repository,
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
            certificate_validator,
            blob_storage_provider,
            handle_invitation_operations,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_custom_version(
        client: Arc<dyn HttpClient>,
        credential_repository: Arc<dyn CredentialRepository>,
        validity_credential_repository: Arc<dyn ValidityCredentialRepository>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        certificate_validator: Arc<dyn CertificateValidator>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        base_url: Option<String>,
        config: Arc<CoreConfig>,
        params: OpenID4VCIDraft13Params,
        protocol_version: &str,
        handle_invitation_operations: Arc<dyn HandleInvitationOperations>,
    ) -> Self {
        let protocol_base_url = base_url
            .as_ref()
            .map(|url| format!("{url}/ssi/openid4vci/{protocol_version}"));
        Self {
            client,
            credential_repository,
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
            certificate_validator,
            blob_storage_provider,
            handle_invitation_operations,
        }
    }

    async fn validate_credential_issuable(
        &self,
        credential_id: &CredentialId,
        latest_state: &CredentialStateEnum,
        format: &str,
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

    fn mso_minimum_refresh_time(&self, format: &str) -> Result<Duration, IssuanceProtocolError> {
        self.config
            .format
            .get::<mdoc_formatter::Params>(format)
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

        let request = self
            .client
            .post(token_endpoint.as_str())
            .form(&form)
            .context("Invalid token_endpoint request")
            .map_err(IssuanceProtocolError::Transport)?;

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

    async fn holder_process_accepted_credential(
        &self,
        issuer_response: SubmitIssuerResponse,
        credential: &Credential,
        storage_access: &StorageAccess,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        fn detect_format_with_crypto_suite(
            credential_schema_format: &str,
            credential_content: &str,
        ) -> anyhow::Result<String> {
            let format = if credential_schema_format.starts_with("JSON_LD") {
                map_from_oidc_format_to_core_detailed("ldp_vc", Some(credential_content))
                    .map_err(|_| anyhow::anyhow!("Credential format not resolved"))?
            } else {
                credential_schema_format.to_owned()
            };
            Ok(format)
        }

        let real_format =
            detect_format_with_crypto_suite(&schema.format, &issuer_response.credential)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let formatter = self
            .formatter_provider
            .get_credential_formatter(&real_format)
            .ok_or_else(|| {
                IssuanceProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
            certificate_validator: self.certificate_validator.clone(),
        });
        let response_credential = formatter
            .extract_credentials(
                &issuer_response.credential,
                credential.schema.as_ref(),
                verification_fn,
                None,
            )
            .await
            .map_err(|e| IssuanceProtocolError::CredentialVerificationFailed(e.into()))?;

        validate_issuance_time(&response_credential.valid_from, formatter.get_leeway())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        validate_expiration_time(&response_credential.valid_until, formatter.get_leeway())
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;
        validate_issuer(
            credential,
            &response_credential,
            self.key_algorithm_provider.as_ref(),
        )
        .await?;

        let layout = schema.layout_properties.clone();

        let (layout_type, layout_properties) = if let (None, Some(metadata)) = (
            layout,
            response_credential
                .credential_schema
                .and_then(|schema| schema.metadata),
        ) {
            (Some(metadata.layout_type), Some(metadata.layout_properties))
        } else {
            (None, None)
        };

        // Revocation method must be updated based on the issued credential (unknown in credential offer).
        // Revocation method should be the same for every credential in list.
        let revocation_method = if let Some(credential_status) = response_credential.status.first()
        {
            let (_, revocation_method) = self
                .revocation_provider
                .get_revocation_method_by_status_type(&credential_status.r#type)
                .ok_or(IssuanceProtocolError::Failed(format!(
                    "Revocation method not found for status type {}",
                    credential_status.r#type
                )))?;
            Some(revocation_method)
        } else {
            None
        };

        let organisation = schema
            .organisation
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed(
                "Missing credential schema organisation".to_string(),
            ))?;

        let identifier_updates = match response_credential.issuer {
            IdentifierDetails::Did(did) => {
                prepare_did_identifier(
                    did,
                    organisation,
                    storage_access,
                    &*self.did_method_provider,
                )
                .await?
            }
            IdentifierDetails::Certificate(certificate) => {
                prepare_certificate_identifier(certificate, organisation, storage_access).await?
            }
            IdentifierDetails::Key(public_key) => {
                prepare_key_identifier(
                    &public_key,
                    organisation,
                    storage_access,
                    self.key_algorithm_provider.as_ref(),
                )
                .await?
            }
        };
        let redirect_uri = issuer_response.redirect_uri.clone();

        Ok(UpdateResponse {
            result: issuer_response,
            create_did: identifier_updates.create_did,
            create_certificate: identifier_updates.create_certificate,
            create_identifier: identifier_updates.create_identifier,
            update_credential_schema: Some(UpdateCredentialSchemaRequest {
                id: schema.id,
                revocation_method,
                format: Some(real_format),
                claim_schemas: None,
                layout_type,
                layout_properties,
            }),
            create_credential_schema: None,
            update_credential: Some((
                credential.id,
                UpdateCredentialRequest {
                    issuer_identifier_id: Some(identifier_updates.issuer_identifier_id),
                    issuer_certificate_id: identifier_updates.issuer_certificate_id,
                    redirect_uri: Some(redirect_uri),
                    suspend_end_date: Clearable::DontTouch,
                    issuance_date: response_credential.issuance_date,
                    ..Default::default()
                },
            )),
            create_credential: None,
            create_key: identifier_updates.create_key,
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
        schema: &CredentialSchema,
        nonce: Option<String>,
        auth_fn: AuthenticationFn,
        access_token: &str,
    ) -> Result<SubmitIssuerResponse, IssuanceProtocolError> {
        let format_type = self
            .config
            .format
            .get_fields(&schema.format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        let oid4vc_format = map_to_openid4vp_format(&format_type)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

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
            auth_fn.get_key_id(),
            jwk,
            nonce,
            auth_fn,
        )
        .await
        .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match oid4vc_format {
            "mso_mdoc" => (None, Some(schema.schema_id.to_owned())),
            _ => (
                Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                None,
            ),
        };

        let body = OpenID4VCICredentialRequestDTO {
            format: oid4vc_format.to_owned(),
            vct: (format_type == FormatType::SdJwtVc).then_some(schema.schema_id.to_owned()),
            doctype,
            proof: OpenID4VCIProofRequestDTO {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
            credential_definition,
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

        response
            .json()
            .context("parsing error")
            .map_err(IssuanceProtocolError::Transport)
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
impl IssuanceProtocol for OpenID4VCI13 {
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
        self.holder_handle_invitation_with_protocol(
            url,
            organisation,
            IssuanceProtocolType::OpenId4VciDraft13,
            storage_access,
            redirect_uri,
        )
        .await
    }

    async fn holder_accept_credential(
        &self,
        mut interaction: Interaction,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        _holder_wallet_unit_id: Option<HolderWalletUnitId>,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, IssuanceProtocolError> {
        let credential = storage_access
            .get_credential_by_interaction_id(&interaction.id)
            .await
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?;

        let schema = credential
            .schema
            .as_ref()
            .ok_or(IssuanceProtocolError::Failed("schema is None".to_string()))?;

        let format_type = self
            .config
            .format
            .get_fields(&schema.format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data.as_ref())?;

        let token_response = self.holder_fetch_token(&interaction_data, tx_code).await?;

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
        if format_type == FormatType::Mdoc {
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
            interaction_data.nonce = token_response.c_nonce.clone();
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
                schema,
                token_response.c_nonce,
                auth_fn,
                token_response.access_token.expose_secret(),
            )
            .await?;

        let notification_id = credential_response.notification_id.to_owned();

        interaction_data.notification_id = notification_id.clone();
        interaction.data = Some(serialize_interaction_data(&interaction_data)?);
        storage_access
            .update_interaction(interaction.id, interaction.into())
            .await
            .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

        let result = self
            .holder_process_accepted_credential(credential_response, &credential, storage_access)
            .await;

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

        let credential_subject =
            credentials_format(credential_schema.wallet_storage_type, &claims, true)
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
                nonce: None,
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

        let format = credential_schema.format;

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

        let format_type = self
            .config
            .format
            .get_fields(&format)
            .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
            .r#type;

        match (format_type, credential_state) {
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
        self.holder_continue_issuance_with_protocol(
            continue_issuance_dto,
            organisation,
            IssuanceProtocolType::OpenId4VciDraft13,
            storage_access,
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

impl OpenID4VCI13 {
    pub(super) async fn holder_handle_invitation_with_protocol(
        &self,
        url: Url,
        organisation: Organisation,
        protocol: IssuanceProtocolType,
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
            protocol,
            &*self.client,
            &*self.certificate_validator,
            storage_access,
            &*self.handle_invitation_operations,
            redirect_uri,
            &self.config,
        )
        .await
    }

    pub(super) async fn holder_continue_issuance_with_protocol(
        &self,
        continue_issuance_dto: ContinueIssuanceDTO,
        organisation: Organisation,
        protocol: IssuanceProtocolType,
        storage_access: &StorageAccess,
    ) -> Result<ContinueIssuanceResponseDTO, IssuanceProtocolError> {
        handle_continue_issuance(
            continue_issuance_dto,
            organisation,
            protocol,
            &*self.client,
            storage_access,
            &*self.handle_invitation_operations,
            self.config.as_ref(),
        )
        .await
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    protocol: IssuanceProtocolType,
    client: &dyn HttpClient,
    certificate_validator: &dyn CertificateValidator,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
    redirect_uri: Option<String>,
    config: &CoreConfig,
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

            let (_, issuer_metadata) =
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

    let remote_identifier = match (
        credential_offer.issuer_did,
        credential_offer.issuer_certificate,
    ) {
        (Some(issuer_did), None) => Some(
            storage_access
                .get_or_create_identifier(
                    &Some(organisation.clone()),
                    &IdentifierDetails::Did(issuer_did),
                    IdentifierRole::Issuer,
                )
                .await
                .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?,
        ),
        (None, Some(issuer_certificate)) => {
            let ParsedCertificate {
                attributes:
                    CertificateX509AttributesDTO {
                        fingerprint,
                        not_after,
                        ..
                    },
                subject_common_name,
                ..
            } = certificate_validator
                .parse_pem_chain(
                    &issuer_certificate,
                    CertificateValidationOptions::signature_and_revocation(None),
                )
                .await
                .map_err(|err| {
                    IssuanceProtocolError::Failed(format!("Invalid issuer certificate: {err}"))
                })?;

            Some(
                storage_access
                    .get_or_create_identifier(
                        &Some(organisation.clone()),
                        &IdentifierDetails::Certificate(CertificateDetails {
                            chain: issuer_certificate,
                            fingerprint,
                            expiry: not_after,
                            subject_common_name,
                        }),
                        IdentifierRole::Issuer,
                    )
                    .await
                    .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?,
            )
        }
        (Some(_), Some(_)) => {
            return Err(IssuanceProtocolError::InvalidRequest(
                "Invalid credential offer: issuer_did and issuer_certificate both present"
                    .to_string(),
            ));
        }
        (None, None) => None,
    };

    let (issuer, issuer_certificate) = remote_identifier
        .map(|(identifier, relation)| {
            (
                Some(identifier),
                if let RemoteIdentifierRelation::Certificate(certificate) = relation {
                    Some(certificate)
                } else {
                    None
                },
            )
        })
        .unwrap_or((None, None));

    let tx_code = credential_offer.grants.tx_code().cloned();

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            IssuanceProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (token_endpoint, issuer_metadata) =
        get_discovery_and_issuer_metadata(client, &credential_issuer_endpoint).await?;

    let (interaction_id, credentials, wallet_storage_type) =
        prepare_issuance_interaction_and_credentials_with_claims(
            organisation,
            token_endpoint,
            issuer_metadata,
            credential_offer.grants,
            &credential_offer.credential_configuration_ids,
            issuer,
            issuer_certificate,
            credential_offer.credential_subject.as_ref(),
            storage_access,
            handle_invitation_operations,
            None,
            config,
        )
        .await?;

    for mut credential in credentials {
        credential.protocol = protocol.to_string();
        storage_access
            .create_credential(credential)
            .await
            .map_err(IssuanceProtocolError::StorageAccessError)?;
    }

    Ok(InvitationResponseEnum::Credential {
        interaction_id,
        tx_code,
        wallet_storage_type,
    })
}

#[allow(clippy::too_many_arguments)]
async fn handle_continue_issuance(
    continue_issuance_dto: ContinueIssuanceDTO,
    organisation: Organisation,
    protocol: IssuanceProtocolType,
    client: &dyn HttpClient,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
    config: &CoreConfig,
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

    let (token_endpoint, issuer_metadata) =
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

    let (interaction_id, credentials, wallet_storage_type) =
        prepare_issuance_interaction_and_credentials_with_claims(
            organisation,
            token_endpoint,
            issuer_metadata,
            OpenID4VCIGrants::AuthorizationCode(OpenID4VCIAuthorizationCodeGrant {
                issuer_state: None, // issuer state was used at the authorization request stage so it is not relevant anymore
                authorization_server: continue_issuance_dto.authorization_server.to_owned(),
            }),
            &all_credential_configuration_ids,
            None,
            None,
            None,
            storage_access,
            handle_invitation_operations,
            Some(continue_issuance_dto),
            config,
        )
        .await?;

    for mut credential in credentials {
        credential.protocol = protocol.to_string();
        storage_access
            .create_credential(credential)
            .await
            .map_err(IssuanceProtocolError::StorageAccessError)?;
    }

    Ok(ContinueIssuanceResponseDTO {
        interaction_id,
        wallet_storage_type,
    })
}

#[allow(clippy::too_many_arguments)]
async fn prepare_issuance_interaction_and_credentials_with_claims(
    organisation: Organisation,
    token_endpoint: String,
    issuer_metadata: OpenID4VCIIssuerMetadataResponseDTO,
    grants: OpenID4VCIGrants,
    configuration_ids: &[String],
    issuer: Option<Identifier>,
    issuer_certificate: Option<Certificate>,
    credential_subject: Option<&ExtendedSubjectDTO>,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
    continue_issuance: Option<ContinueIssuanceDTO>,
    config: &CoreConfig,
) -> Result<
    (
        InteractionId,
        Vec<Credential>,
        Option<WalletStorageTypeEnum>,
    ),
    IssuanceProtocolError,
> {
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

    let schema_id = resolve_schema_id(credential_config).unwrap_or(configuration_id.clone());

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer.clone(),
        credential_endpoint: issuer_metadata.credential_endpoint.clone(),
        notification_endpoint: issuer_metadata.notification_endpoint.to_owned(),
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
        nonce: None,
        notification_id: None,
    };
    let data = serialize_interaction_data(&holder_data)?;

    let interaction =
        create_and_store_interaction(storage_access, data, Some(organisation.clone())).await?;
    let interaction_id = interaction.id;

    let credential_id: CredentialId = Uuid::new_v4().into();
    let (claims, credential_schema) = match storage_access
        .get_schema(&schema_id, organisation.id)
        .await
        .map_err(IssuanceProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            let format_type = config
                .format
                .get_fields(&credential_schema.format)
                .map_err(|e| IssuanceProtocolError::Failed(e.to_string()))?
                .r#type;
            if !has_matching_format(credential_config, format_type) {
                return Err(IssuanceProtocolError::IncorrectCredentialSchemaType);
            }
            let claims_with_values = build_claim_keys(credential_config, credential_subject)
                .and_then(|claim_keys| {
                    extract_offered_claims(&credential_schema, credential_id, &claim_keys)
                });

            let claims = claims_with_values.unwrap_or_else(|e| {
                tracing::warn!(%e, "failed to parse offered claims for external schema");
                // For external (predefined) schemas we accept failure.
                // The claim schemas could be not specified in the offer and metadata
                // The offered credential will have no claims, but we will receive them
                // when the offer is accepted.
                vec![]
            });

            (claims, credential_schema)
        }
        None => {
            let claim_keys = build_claim_keys(credential_config, credential_subject)?;

            let BuildCredentialSchemaResponse { claims, schema } = handle_invitation_operations
                .create_new_schema(
                    BasicSchemaData {
                        id: schema_id,
                        offer_id: configuration_id.clone(),
                    },
                    &claim_keys,
                    &credential_id,
                    credential_config,
                    &issuer_metadata,
                    organisation.clone(),
                )
                .await?;
            (claims, schema)
        }
    };

    let credential = create_credential(
        credential_id,
        credential_schema,
        claims,
        interaction,
        None,
        issuer,
        issuer_certificate,
    );

    Ok((
        interaction_id,
        vec![credential],
        credential_config.wallet_storage_type,
    ))
}
fn has_matching_format(
    credential_config: &OpenID4VCICredentialConfigurationData,
    format_type: FormatType,
) -> bool {
    match credential_config.format.as_str() {
        "jwt_vc_json" | "jwt_vp_json" => format_type == FormatType::Jwt,
        "vc+sd-jwt" | "dc+sd-jwt" | "vc sd-jwt" => {
            [FormatType::SdJwt, FormatType::SdJwtVc].contains(&format_type)
        }
        "ldp_vc" => [FormatType::JsonLdClassic, FormatType::JsonLdBbsPlus].contains(&format_type),
        "ldp_vp" => format_type == FormatType::JsonLdClassic,
        "mso_mdoc" => format_type == FormatType::Mdoc,
        _ => false,
    }
}

fn resolve_schema_id(credential_config: &OpenID4VCICredentialConfigurationData) -> Option<String> {
    match credential_config.format.as_str() {
        "mso_mdoc" => credential_config.doctype.clone(),
        // external sd-jwt vc
        "vc+sd-jwt" | "dc+sd-jwt" => {
            // We use the vc+sd-jwt format identifier for both SD-JWT-VC and SD-JWT credential formats.
            credential_config.vct.clone()
        }
        _ => None,
    }
}

async fn resolve_credential_offer(
    client: &dyn HttpClient,
    invitation_url: Url,
) -> Result<OpenID4VCICredentialOfferDTO, IssuanceProtocolError> {
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
) -> Result<(String, OpenID4VCIIssuerMetadataResponseDTO), IssuanceProtocolError> {
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

    let append_url_path = |path: &str| {
        let mut openid_configuration_url = credential_issuer_endpoint.to_owned();
        openid_configuration_url
            .path_segments_mut()
            .map_err(|_| {
                IssuanceProtocolError::Failed(format!(
                    "Invalid credential_issuer_endpoint URL: {credential_issuer_endpoint}",
                ))
            })?
            .extend(path.split("/"));

        Ok(openid_configuration_url.to_string())
    };

    let token_endpoint_future = async {
        let url = append_url_path(".well-known/oauth-authorization-server")?;
        let response = client
            .get(&url)
            .send()
            .await
            .context("send error")
            .map_err(IssuanceProtocolError::Transport)?;

        if response.status.0 == 404 {
            // Fallback for https://datatracker.ietf.org/doc/html/rfc8414#section-3,
            // since there is no specification where to obtain the token endpoint
            // if the issuer is not providing .well-known/oauth-authorization-server
            Ok(format!("{credential_issuer_endpoint}/token"))
        } else {
            let oidc_discovery: OAuthAuthorizationServerMetadata = response
                .error_for_status()
                .context("status error")
                .map_err(IssuanceProtocolError::Transport)?
                .json()
                .context("parsing error")
                .map_err(IssuanceProtocolError::Transport)?;
            Ok(oidc_discovery
                .token_endpoint
                .ok_or(IssuanceProtocolError::Failed(
                    "Missing token endpoint".to_string(),
                ))?
                .to_string())
        }
    };

    let issuer_metadata = fetch(
        client,
        append_url_path(".well-known/openid-credential-issuer")?,
    );
    tokio::try_join!(token_endpoint_future, issuer_metadata)
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

fn build_claim_keys(
    credential_configuration: &OpenID4VCICredentialConfigurationData,
    credential_subject: Option<&ExtendedSubjectDTO>,
) -> Result<IndexMap<String, OpenID4VCICredentialValueDetails>, IssuanceProtocolError> {
    let claim_object = match (
        &credential_configuration.credential_definition,
        &credential_configuration.claims,
    ) {
        (None, None) | (Some(_), Some(_)) => {
            return Err(IssuanceProtocolError::Failed(
                "Incorrect or missing credential claims".to_string(),
            ));
        }
        (None, Some(mdoc_claims)) => mdoc_claims,
        (Some(credential_definition), None) => credential_definition
            .credential_subject
            .as_ref()
            .ok_or_else(|| {
                IssuanceProtocolError::Failed("Missing credential subject".to_string())
            })?,
    };

    let keys = credential_subject
        .and_then(|cs| cs.keys.clone())
        .unwrap_or_default();

    if !keys.claims.is_empty() {
        return Ok(keys.claims);
    }

    let keys = collect_keys(claim_object, None);
    Ok(keys
        .into_iter()
        .map(|(path, value_type)| {
            (
                path,
                OpenID4VCICredentialValueDetails {
                    value: None,
                    value_type,
                },
            )
        })
        .collect())
}

fn collect_keys(
    claim_object: &OpenID4VCICredentialSubjectItem,
    item_path: Option<&str>,
) -> Vec<(String, String)> {
    let mut item_paths = Vec::new();

    if let Some(claims) = claim_object.claims.as_ref() {
        for (key, object) in claims {
            let path = if let Some(item_path) = &item_path {
                format!("{item_path}{NESTED_CLAIM_MARKER}{key}")
            } else {
                key.to_owned()
            };
            let paths = collect_keys(object, Some(&path));

            item_paths.extend(paths);
        }
    }

    if let Some(arrays) = claim_object.arrays.as_ref() {
        for (key, object_definitions) in arrays {
            if let Some(object_fields) = object_definitions.first() {
                let path = if let Some(item_path) = &item_path {
                    format!("{item_path}{NESTED_CLAIM_MARKER}{key}{NESTED_CLAIM_MARKER}0")
                } else {
                    format!("{key}{NESTED_CLAIM_MARKER}0")
                };
                let paths = collect_keys(object_fields, Some(&path));

                item_paths.extend(paths);
            }
        }
    }

    // Break condition - we reached top claim and it suppose to have a value
    if claim_object.arrays.is_none() && claim_object.claims.is_none() {
        item_paths.push((
            item_path.unwrap_or_default().to_string(),
            claim_object
                .value_type
                .as_ref()
                .cloned()
                .unwrap_or("STRING".to_owned()),
        ));
    }

    item_paths
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
    certificate: CertificateDetails,
    organisation: &Organisation,
    storage_access: &StorageAccess,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
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
            let id = Uuid::new_v4().into();
            let identifier_id: IdentifierId = Uuid::new_v4().into();
            let certificate = Certificate {
                id,
                identifier_id,
                name: certificate
                    .subject_common_name
                    .unwrap_or(format!("issuer certificate {id}")),
                chain: certificate.chain,
                fingerprint: certificate.fingerprint,
                state: CertificateState::Active,
                created_date: now,
                last_modified: now,
                organisation_id: Some(organisation.id),
                expiry_date: certificate.expiry,
                key: None,
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
    public_key: &PublicKeyJwk,
    organisation: &Organisation,
    storage_access: &StorageAccess,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<IdentifierUpdates, IssuanceProtocolError> {
    let parsed_key = key_algorithm_provider
        .parse_jwk(public_key)
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;
    let now = OffsetDateTime::now_utc();

    let key = storage_access
        .get_key_by_raw_key_and_type(
            parsed_key.key.public_key_as_raw(),
            parsed_key.algorithm_type,
            organisation.id,
        )
        .await
        .map_err(|err| IssuanceProtocolError::Failed(err.to_string()))?;

    let (key, create_key) = if let Some(key) = key {
        (key, None)
    } else {
        let key_id = Uuid::new_v4().into();
        let key = Key {
            id: key_id,
            created_date: now,
            last_modified: now,
            name: format!("Issuer {key_id}"),
            organisation: Some(organisation.clone()),
            public_key: parsed_key.key.public_key_as_raw(),
            key_reference: None,
            storage_type: "INTERNAL".to_string(),
            key_type: parsed_key.algorithm_type.to_string(),
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
