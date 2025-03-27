use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use indexmap::IndexMap;
use mappers::map_credential_formats_to_presentation_format;
use one_crypto::encryption::encrypt_string;
use one_crypto::utilities;
use secrecy::ExposeSecret;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use shared_types::{CredentialId, KeyId};
use time::{Duration, OffsetDateTime};
use url::Url;
use utils::{
    deserialize_interaction_data, interaction_data_from_query, serialize_interaction_data,
    validate_interaction_data,
};
use uuid::Uuid;

use super::mapper::{
    create_credential, create_open_id_for_vp_presentation_definition,
    create_open_id_for_vp_sharing_url_encoded, create_presentation_submission,
    get_credential_offer_url, map_offered_claims_to_credential_schema,
};
use super::model::{
    ClientIdScheme, ExtendedSubjectDTO, HolderInteractionData, InvitationResponseDTO, JwePayload,
    OpenID4VCICredential, OpenID4VCICredentialConfigurationData,
    OpenID4VCICredentialDefinitionRequestDTO, OpenID4VCICredentialOfferClaim,
    OpenID4VCICredentialOfferDTO, OpenID4VCICredentialSubjectItem,
    OpenID4VCICredentialValueDetails, OpenID4VCIDiscoveryResponseDTO,
    OpenID4VCIIssuerInteractionDataDTO, OpenID4VCIIssuerMetadataResponseDTO, OpenID4VCIProof,
    OpenID4VCITokenRequestDTO, OpenID4VCITokenResponseDTO, OpenID4VCParams,
    OpenID4VPDirectPostResponseDTO, OpenID4VPHolderInteractionData,
    OpenID4VPVerifierInteractionContent, OpenID4VpPresentationFormat, PresentedCredential,
    ShareResponse, SubmitIssuerResponse, UpdateResponse,
};
use super::proof_formatter::OpenID4VCIProofJWTFormatter;
use super::service::{create_credential_offer, FnMapExternalFormatToExternalDetailed};
use super::{
    ExchangeProtocolError, FormatMapper, HandleInvitationOperationsAccess, StorageAccess,
    TypeToDescriptorMapper,
};
use crate::common_mapper::{DidRole, NESTED_CLAIM_MARKER};
use crate::model::credential::{Clearable, Credential, UpdateCredentialRequest};
use crate::model::credential_schema::UpdateCredentialSchemaRequest;
use crate::model::did::{Did, DidType, KeyRole};
use crate::model::interaction::Interaction;
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::model::proof::{Proof, ProofStateEnum, UpdateProofRequest};
use crate::provider::credential_formatter::mdoc_formatter::mdoc::{
    OID4VPHandover, SessionTranscript,
};
use crate::provider::credential_formatter::model::{DetailCredential, FormatPresentationCtx};
use crate::provider::credential_formatter::provider::CredentialFormatterProvider;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::dto::ExchangeProtocolCapabilities;
use crate::provider::exchange_protocol::error::TxCodeError;
use crate::provider::exchange_protocol::iso_mdl::common::to_cbor;
use crate::provider::exchange_protocol::mapper::{
    interaction_from_handle_invitation, proof_from_handle_invitation,
};
use crate::provider::exchange_protocol::openid4vc::model::OpenID4VCICredentialOfferClaimValue;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::oidc::service::credentials_format;
use crate::util::key_verification::KeyVerification;

pub mod mappers;
mod mdoc;
mod utils;
mod x509;

#[cfg(test)]
mod test;

const CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY: &str = "credential_offer";
const CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY: &str = "credential_offer_uri";
const PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY: &str = "presentation_definition";
const PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY: &str = "presentation_definition_uri";
const REQUEST_URI_QUERY_PARAM_KEY: &str = "request_uri";
const REQUEST_QUERY_PARAM_KEY: &str = "request";

pub struct OpenID4VCHTTP {
    client: Arc<dyn HttpClient>,
    formatter_provider: Arc<dyn CredentialFormatterProvider>,
    revocation_provider: Arc<dyn RevocationMethodProvider>,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    key_provider: Arc<dyn KeyProvider>,
    base_url: Option<String>,
    params: OpenID4VCParams,
}

enum InvitationType {
    CredentialIssuance,
    ProofRequest,
}

#[allow(clippy::too_many_arguments)]
impl OpenID4VCHTTP {
    pub fn new(
        base_url: Option<String>,
        formatter_provider: Arc<dyn CredentialFormatterProvider>,
        revocation_provider: Arc<dyn RevocationMethodProvider>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        key_provider: Arc<dyn KeyProvider>,
        client: Arc<dyn HttpClient>,
        params: OpenID4VCParams,
    ) -> Self {
        Self {
            base_url,
            formatter_provider,
            revocation_provider,
            did_method_provider,
            key_algorithm_provider,
            key_provider,
            client,
            params,
        }
    }

    fn detect_invitation_type(&self, url: &Url) -> Option<InvitationType> {
        let query_has_key = |name| url.query_pairs().any(|(key, _)| name == key);

        if !self.params.issuance.disabled
            && self.params.issuance.url_scheme == url.scheme()
            && (query_has_key(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY)
                || query_has_key(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY))
        {
            return Some(InvitationType::CredentialIssuance);
        }

        if !self.params.presentation.disabled
            && self.params.presentation.url_scheme == url.scheme()
            && (query_has_key(PRESENTATION_DEFINITION_VALUE_QUERY_PARAM_KEY)
                || query_has_key(PRESENTATION_DEFINITION_REFERENCE_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_URI_QUERY_PARAM_KEY)
                || query_has_key(REQUEST_QUERY_PARAM_KEY))
        {
            return Some(InvitationType::ProofRequest);
        }

        None
    }

    pub fn can_handle(&self, url: &Url) -> bool {
        self.detect_invitation_type(url).is_some()
    }

    pub async fn holder_handle_invitation(
        &self,
        url: Url,
        organisation: Organisation,
        storage_access: &StorageAccess,
        handle_invitation_operations: &HandleInvitationOperationsAccess,
    ) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
        let invitation_type =
            self.detect_invitation_type(&url)
                .ok_or(ExchangeProtocolError::Failed(
                    "No OpenID4VC query params detected".to_string(),
                ))?;

        match invitation_type {
            InvitationType::CredentialIssuance => {
                handle_credential_invitation(
                    url,
                    organisation,
                    &self.client,
                    storage_access,
                    handle_invitation_operations,
                )
                .await
            }
            InvitationType::ProofRequest => {
                handle_proof_invitation(
                    url,
                    self.params.allow_insecure_http_transport,
                    &self.client,
                    storage_access,
                    Some(organisation),
                    &self.key_algorithm_provider,
                    &self.did_method_provider,
                    &self.params,
                )
                .await
            }
        }
    }

    pub async fn holder_reject_proof(&self, _proof: &Proof) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn holder_submit_proof(
        &self,
        proof: &Proof,
        credential_presentations: Vec<PresentedCredential>,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        // LOCAL_CREDENTIAL_FORMAT -> oidc_vc_format
        format_map: HashMap<String, String>,
        // oidc_vp_format -> LOCAL_PRESENTATION_FORMAT
        presentation_format_map: HashMap<String, String>,
    ) -> Result<UpdateResponse<()>, ExchangeProtocolError> {
        let interaction = proof
            .interaction
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let interaction_data: OpenID4VPHolderInteractionData =
            deserialize_interaction_data(interaction.data)?;

        let tokens: Vec<String> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.presentation.to_owned())
            .collect();

        let formats: HashMap<&str, &str> = credential_presentations
            .iter()
            .map(|presented_credential| {
                format_map
                    .get(presented_credential.credential_schema.format.as_str())
                    .map(|mapped| {
                        (
                            mapped.as_str(),
                            presented_credential.credential_schema.format.as_str(),
                        )
                    })
            })
            .collect::<Option<_>>()
            .ok_or_else(|| ExchangeProtocolError::Failed("missing format mapping".into()))?;

        let (_has_mdoc, format, oidc_format) =
            map_credential_formats_to_presentation_format(&formats, &format_map)?;

        let presentation_format =
            presentation_format_map
                .get(&oidc_format)
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Missing presentation format for `{oidc_format}`"
                )))?;

        let presentation_formatter = self
            .formatter_provider
            .get_formatter(presentation_format)
            .ok_or_else(|| ExchangeProtocolError::Failed("Formatter not found".to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                &key.to_owned(),
                jwk_key_id,
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let presentation_definition_id = interaction_data
            .presentation_definition
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "presentation_definition is None".to_string(),
            ))?
            .id
            .to_owned();

        let token_formats: Vec<_> = credential_presentations
            .iter()
            .map(|presented_credential| presented_credential.credential_schema.format.to_owned())
            .collect();

        let presentation_submission = create_presentation_submission(
            presentation_definition_id,
            credential_presentations,
            &oidc_format,
            format_map.clone(),
        )?;

        let mut params: HashMap<&str, String> = HashMap::new();

        let response_uri =
            interaction_data
                .response_uri
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "response_uri is None".to_string(),
                ))?;
        let nonce = interaction_data
            .nonce
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("nonce is None".to_string()))?;

        if format == "MDOC" {
            let mdoc_generated_nonce = utilities::generate_nonce();

            let ctx = FormatPresentationCtx {
                mdoc_session_transcript: Some(
                    to_cbor(&SessionTranscript {
                        handover: OID4VPHandover::compute(
                            interaction_data.client_id.as_str().trim_end_matches('/'),
                            response_uri.as_str().trim_end_matches('/'),
                            nonce,
                            &mdoc_generated_nonce,
                        )
                        .into(),
                        device_engagement_bytes: None,
                        e_reader_key_bytes: None,
                    })
                    .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
                ),
                ..Default::default()
            };

            let mut client_metadata =
                interaction_data
                    .client_metadata
                    .ok_or(ExchangeProtocolError::Failed(
                        "Missing client_metadata for MDOC openid4vp".to_string(),
                    ))?;

            if client_metadata.jwks.keys.is_empty() {
                if let Some(ref uri) = client_metadata.jwks_uri {
                    let jwks = self
                        .client
                        .get(uri)
                        .send()
                        .await
                        .context("send error")
                        .map_err(ExchangeProtocolError::Transport)?
                        .error_for_status()
                        .context("status error")
                        .map_err(ExchangeProtocolError::Transport)?;

                    client_metadata.jwks = jwks
                        .json()
                        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
                }
            }

            let vp_token = presentation_formatter
                .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
                .await
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            let payload = JwePayload {
                aud: response_uri.clone(),
                exp: OffsetDateTime::now_utc() + Duration::minutes(10),
                vp_token,
                presentation_submission,
                state: interaction_data.state,
            };

            let response = mdoc::build_jwe(
                payload,
                client_metadata,
                &mdoc_generated_nonce,
                nonce,
                &*self.key_algorithm_provider,
            )
            .await
            .map_err(|err| {
                ExchangeProtocolError::Failed(format!("Failed to build mdoc response jwe: {err}"))
            })?;

            params.insert("response", response);
        } else {
            let ctx = FormatPresentationCtx {
                nonce: Some(nonce.clone()),
                token_formats: Some(token_formats),
                vc_format_map: format_map,
                ..Default::default()
            };

            let vp_token = presentation_formatter
                .format_presentation(&tokens, &holder_did.did, &key.key_type, auth_fn, ctx)
                .await
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            params.insert("vp_token", vp_token);
            params.insert(
                "presentation_submission",
                serde_json::to_string(&presentation_submission)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
            );

            if let Some(state) = interaction_data.state {
                params.insert("state", state);
            }
        }

        let response = self
            .client
            .post(response_uri.as_str())
            .form(&params)
            .context("form error")
            .map_err(ExchangeProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;

        let response: Result<OpenID4VPDirectPostResponseDTO, _> = response.json();

        if let Ok(value) = response {
            Ok(UpdateResponse {
                result: (),
                update_proof: Some(UpdateProofRequest {
                    redirect_uri: Some(value.redirect_uri),
                    ..Default::default()
                }),
                create_did: None,
                update_credential: None,
                update_credential_schema: None,
            })
        } else {
            Ok(UpdateResponse {
                result: (),
                update_proof: None,
                create_did: None,
                update_credential: None,
                update_credential_schema: None,
            })
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn holder_accept_credential(
        &self,
        credential: &Credential,
        holder_did: &Did,
        key: &Key,
        jwk_key_id: Option<String>,
        credential_format: &str,
        storage_access: &StorageAccess,
        tx_code: Option<String>,
        map_external_format_to_external_detailed: FnMapExternalFormatToExternalDetailed,
    ) -> Result<UpdateResponse<SubmitIssuerResponse>, ExchangeProtocolError> {
        let schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("schema is None".to_string()))?;

        let mut interaction = credential
            .interaction
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "interaction is None".to_string(),
            ))?
            .to_owned();

        let mut interaction_data: HolderInteractionData =
            deserialize_interaction_data(interaction.data)?;

        let token_endpoint =
            interaction_data
                .token_endpoint
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "token endpoint is missing".to_string(),
                ))?;

        let grants = interaction_data
            .grants
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "grants data is missing".to_string(),
            ))?;

        let token_response: OpenID4VCITokenResponseDTO = async {
            let has_sent_tx_code = tx_code.is_some();

            let request = self
                .client
                .post(token_endpoint.as_str())
                .form(&OpenID4VCITokenRequestDTO::PreAuthorizedCode {
                    pre_authorized_code: grants.code.pre_authorized_code.clone(),
                    tx_code,
                })
                .context("Invalid token_endpoint request")
                .map_err(ExchangeProtocolError::Transport)?;

            let response = request
                .send()
                .await
                .context("Error during token_endpoint response")
                .map_err(ExchangeProtocolError::Transport)?;

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
                        return Err(ExchangeProtocolError::TxCode(TxCodeError::IncorrectCode));
                    }
                    Ok(OpenId4VciError::InvalidRequest) => {
                        return Err(ExchangeProtocolError::TxCode(TxCodeError::InvalidCodeUse));
                    }
                    Err(_) => {}
                }
            }

            response
                .error_for_status()
                .context("status error")
                .map_err(ExchangeProtocolError::Transport)?
                .json()
                .context("parsing error")
                .map_err(ExchangeProtocolError::Transport)
        }
        .await?;

        // only mdoc credentials support refreshing, do not store the tokens otherwise
        if credential_format == "mso_mdoc" {
            let encrypted_access_token = encrypt_string(
                &token_response.access_token,
                &self.params.encryption,
            )
            .map_err(|err| {
                ExchangeProtocolError::Failed(format!("failed to encrypt access token: {err}"))
            })?;
            interaction_data.access_token = Some(encrypted_access_token);
            interaction_data.access_token_expires_at =
                OffsetDateTime::from_unix_timestamp(token_response.expires_in.0).ok();
            interaction_data.refresh_token = token_response
                .refresh_token
                .map(|token| encrypt_string(&token, &self.params.encryption))
                .transpose()
                .map_err(|err| {
                    ExchangeProtocolError::Failed(format!("failed to encrypt refresh token: {err}"))
                })?;
            interaction_data.refresh_token_expires_at = token_response
                .refresh_token_expires_in
                .and_then(|expires_in| OffsetDateTime::from_unix_timestamp(expires_in.0).ok());
        }

        let data = serialize_interaction_data(&interaction_data)?;
        interaction.data = Some(data);

        storage_access
            .update_interaction(interaction.into())
            .await
            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?;

        let auth_fn = self
            .key_provider
            .get_signature_provider(
                &key.to_owned(),
                jwk_key_id.clone(),
                self.key_algorithm_provider.clone(),
            )
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        // Very basic support for JWK as crypto binding method for EUDI
        let jwk = match interaction_data.cryptographic_binding_methods_supported {
            Some(methods) => {
                if methods.contains(&"jwk".to_string()) {
                    let resolved = self
                        .did_method_provider
                        .resolve(&holder_did.did)
                        .await
                        .map_err(|_| {
                            ExchangeProtocolError::Failed(
                                "Could not resolve did method".to_string(),
                            )
                        })?;

                    Some(
                        resolved
                            .verification_method
                            .first()
                            .ok_or(ExchangeProtocolError::Failed(
                                "Could find verification method in resolved did document"
                                    .to_string(),
                            ))?
                            .public_key_jwk
                            .clone()
                            .into(),
                    )
                } else {
                    None
                }
            }
            None => None,
        };

        let proof_jwt = OpenID4VCIProofJWTFormatter::format_proof(
            interaction_data.issuer_url,
            jwk_key_id,
            jwk,
            token_response.c_nonce,
            auth_fn,
        )
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let (credential_definition, doctype) = match credential_format {
            "mso_mdoc" => (None, Some(schema.schema_id.to_owned())),
            _ => (
                Some(OpenID4VCICredentialDefinitionRequestDTO {
                    r#type: vec!["VerifiableCredential".to_string()],
                    credential_subject: None,
                }),
                None,
            ),
        };

        let body = OpenID4VCICredential {
            format: credential_format.to_owned(),
            vct: (schema.format == "SD_JWT_VC").then_some(schema.schema_id.to_owned()),
            doctype,
            proof: OpenID4VCIProof {
                proof_type: "jwt".to_string(),
                jwt: proof_jwt,
            },
            credential_definition,
        };

        let response = self
            .client
            .post(interaction_data.credential_endpoint.as_str())
            .bearer_auth(token_response.access_token.expose_secret())
            .json(&body)
            .context("json error")
            .map_err(ExchangeProtocolError::Transport)?
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?;

        let response = response
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?;
        let response_value: SubmitIssuerResponse = response
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        let real_format =
            map_external_format_to_external_detailed(&schema.format, &response_value.credential)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let formatter = self
            .formatter_provider
            .get_formatter(&real_format)
            .ok_or_else(|| {
                ExchangeProtocolError::Failed(format!("{} formatter not found", schema.format))
            })?;

        let verification_fn = Box::new(KeyVerification {
            key_algorithm_provider: self.key_algorithm_provider.clone(),
            did_method_provider: self.did_method_provider.clone(),
            key_role: KeyRole::AssertionMethod,
        });
        let response_credential = formatter
            .extract_credentials(&response_value.credential, verification_fn, None)
            .await
            .map_err(|e| ExchangeProtocolError::CredentialVerificationFailed(e.into()))?;

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
                .ok_or(ExchangeProtocolError::Failed(format!(
                    "Revocation method not found for status type {}",
                    credential_status.r#type
                )))?;
            Some(revocation_method)
        } else {
            None
        };

        // issuer_did must be set based on issued credential (might be unknown in credential offer)
        let issuer_did_value =
            response_credential
                .issuer_did
                .ok_or(ExchangeProtocolError::Failed(
                    "issuer_did missing".to_string(),
                ))?;

        // check did is consistent with what was offered
        if let Some(ref credential_offer_did) = credential.issuer_did {
            if issuer_did_value != credential_offer_did.did {
                return Err(ExchangeProtocolError::DidMismatch);
            }
        }

        let now = OffsetDateTime::now_utc();
        let (issuer_did_id, create_did) = match storage_access
            .get_did_by_value(&issuer_did_value)
            .await
            .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?
        {
            Some(did) => (did.id, None),
            None => {
                let id = Uuid::new_v4().into();
                let did_method = self
                    .did_method_provider
                    .get_did_method_id(&issuer_did_value)
                    .ok_or(ExchangeProtocolError::Failed(format!(
                        "unsupported issuer did method: {issuer_did_value}"
                    )))?;

                (
                    id,
                    Some(Did {
                        id,
                        name: format!("issuer {id}"),
                        created_date: now,
                        last_modified: now,
                        did: issuer_did_value,
                        did_type: DidType::Remote,
                        did_method,
                        keys: None,
                        deactivated: false,
                        organisation: schema.organisation.clone(),
                    }),
                )
            }
        };

        let redirect_uri = response_value.redirect_uri.clone();

        Ok(UpdateResponse {
            result: response_value,
            update_proof: None,
            create_did,
            update_credential_schema: Some(UpdateCredentialSchemaRequest {
                id: schema.id,
                revocation_method,
                format: Some(real_format),
                claim_schemas: None,
                layout_type,
                layout_properties,
            }),
            update_credential: Some((
                credential.id,
                UpdateCredentialRequest {
                    issuer_did_id: Some(issuer_did_id),
                    redirect_uri: Some(redirect_uri),
                    suspend_end_date: Clearable::DontTouch,
                    ..Default::default()
                },
            )),
        })
    }

    pub async fn holder_reject_credential(
        &self,
        _credential: &Credential,
    ) -> Result<(), ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    pub async fn issuer_share_credential(
        &self,
        credential: &Credential,
        _credential_format: &str,
    ) -> Result<ShareResponse<OpenID4VCIIssuerInteractionDataDTO>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();
        let interaction_content = OpenID4VCIIssuerInteractionDataDTO {
            pre_authorized_code_used: false,
            access_token_hash: Default::default(),
            access_token_expires_at: None,
            refresh_token_hash: None,
            refresh_token_expires_at: None,
        };

        let mut url = Url::parse(&format!("{}://", self.params.issuance.url_scheme))
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        let mut query = url.query_pairs_mut();

        let credential_schema = credential
            .schema
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "credential schema missing".to_string(),
            ))?;

        let url = self
            .base_url
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("Missing base_url".to_owned()))?;

        let wallet_storage_type = credential_schema.wallet_storage_type.clone();

        let claims = credential
            .claims
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed("Missing claims".to_owned()))?
            .iter()
            .map(|claim| claim.to_owned())
            .collect::<Vec<_>>();

        let credential_subject = credentials_format(wallet_storage_type, &claims)
            .map_err(|e| ExchangeProtocolError::Other(e.into()))?;

        if self.params.credential_offer_by_value {
            let issuer_did = credential
                .issuer_did
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "Missing issuer did".to_owned(),
                ))?
                .did
                .clone();
            let offer = create_credential_offer(
                url,
                &interaction_id.to_string(),
                issuer_did,
                &credential_schema.id,
                &credential_schema.schema_id,
                credential_subject,
            )
            .map_err(|e| ExchangeProtocolError::Other(e.into()))?;

            let offer_string = serde_json::to_string(&offer)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

            query.append_pair(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY, &offer_string);
        } else {
            let offer_url = get_credential_offer_url(self.base_url.to_owned(), credential)?;
            query.append_pair(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY, &offer_url);
        }

        Ok(ShareResponse {
            url: query.finish().to_string(),
            interaction_id,
            context: interaction_content,
        })
    }

    pub async fn verifier_share_proof(
        &self,
        proof: &Proof,
        format_to_type_mapper: FormatMapper, // Credential schema format to format type mapper
        key_id: KeyId,
        encryption_key_jwk: PublicKeyJwkDTO,
        vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
        type_to_descriptor: TypeToDescriptorMapper,
        client_id_scheme: ClientIdScheme,
    ) -> Result<ShareResponse<OpenID4VPVerifierInteractionContent>, ExchangeProtocolError> {
        let interaction_id = Uuid::new_v4();

        // Pass the expected presentation content to interaction for verification
        let presentation_definition = create_open_id_for_vp_presentation_definition(
            interaction_id,
            proof,
            type_to_descriptor,
            format_to_type_mapper,
            &*self.formatter_provider,
        )?;

        let Some(base_url) = &self.base_url else {
            return Err(ExchangeProtocolError::Failed("Missing base_url".into()));
        };
        let response_uri = format!("{base_url}/ssi/oidc-verifier/v1/response");
        let nonce = utilities::generate_alphanumeric(32);

        let client_id = match client_id_scheme {
            ClientIdScheme::RedirectUri | ClientIdScheme::VerifierAttestation => {
                response_uri.to_owned()
            }
            ClientIdScheme::X509SanDns => {
                let base_url = Url::parse(base_url)
                    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

                base_url
                    .domain()
                    .ok_or(ExchangeProtocolError::Failed(
                        "Invalid base_url".to_string(),
                    ))?
                    .to_string()
            }
            ClientIdScheme::Did => proof
                .verifier_did
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "proof is missing verifier_did, required for did client_id_scheme".to_string(),
                ))?
                .did
                .to_string(),
        };

        let interaction_content = OpenID4VPVerifierInteractionContent {
            nonce: nonce.to_owned(),
            presentation_definition,
            client_id: client_id.to_owned(),
            client_id_scheme: Some(client_id_scheme),
            response_uri: Some(response_uri),
        };

        let encoded_offer = create_open_id_for_vp_sharing_url_encoded(
            base_url,
            &self.params,
            client_id,
            interaction_id,
            &interaction_content,
            nonce,
            proof,
            key_id,
            encryption_key_jwk,
            vp_formats,
            client_id_scheme,
            &self.key_algorithm_provider,
            &*self.key_provider,
            &*self.did_method_provider,
        )
        .await?;

        Ok(ShareResponse {
            url: format!("{}://?{encoded_offer}", self.params.presentation.url_scheme),
            interaction_id,
            context: interaction_content,
        })
    }

    pub async fn verifier_handle_proof(
        &self,
        _proof: &Proof,
        _submission: &[u8],
    ) -> Result<Vec<DetailCredential>, ExchangeProtocolError> {
        Err(ExchangeProtocolError::OperationNotSupported)
    }

    pub async fn verifier_retract_proof(
        &self,
        _proof: &Proof,
    ) -> Result<(), ExchangeProtocolError> {
        Ok(())
    }

    pub fn get_capabilities(&self) -> ExchangeProtocolCapabilities {
        unimplemented!()
    }
}

async fn handle_credential_invitation(
    invitation_url: Url,
    organisation: Organisation,
    client: &Arc<dyn HttpClient>,
    storage_access: &StorageAccess,
    handle_invitation_operations: &HandleInvitationOperationsAccess,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let credential_offer = resolve_credential_offer(client, invitation_url).await?;

    let issuer_did = match credential_offer.issuer_did {
        Some(issuer_did) => Some(
            storage_access
                .get_or_create_did(&Some(organisation.clone()), &issuer_did, DidRole::Issuer)
                .await
                .map_err(|err| ExchangeProtocolError::Failed(err.to_string()))?,
        ),
        None => None,
    };

    let tx_code = credential_offer.grants.code.tx_code.clone();

    let credential_issuer_endpoint: Url =
        credential_offer.credential_issuer.parse().map_err(|_| {
            ExchangeProtocolError::Failed(format!(
                "Invalid credential issuer url {}",
                credential_offer.credential_issuer
            ))
        })?;

    let (oicd_discovery, issuer_metadata) =
        get_discovery_and_issuer_metadata(client.as_ref(), &credential_issuer_endpoint).await?;

    // We only support one credential at the time now
    let configuration_id = credential_offer
        .credential_configuration_ids
        .first()
        .ok_or_else(|| {
            ExchangeProtocolError::Failed("Credential offer is missing credentials".to_string())
        })?;

    let credential_config = issuer_metadata
        .credential_configurations_supported
        .get(configuration_id)
        .ok_or_else(|| {
            ExchangeProtocolError::Failed(format!(
                "Credential configuration is missing for {configuration_id}"
            ))
        })?;

    let schema_data =
        handle_invitation_operations.find_schema_data(credential_config, configuration_id)?;

    let holder_data = HolderInteractionData {
        issuer_url: issuer_metadata.credential_issuer.clone(),
        credential_endpoint: issuer_metadata.credential_endpoint.clone(),
        token_endpoint: Some(oicd_discovery.token_endpoint),
        grants: Some(credential_offer.grants),
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
    };
    let data = serialize_interaction_data(&holder_data)?;

    let interaction = create_and_store_interaction(
        storage_access,
        credential_issuer_endpoint,
        data,
        Some(organisation.clone()),
    )
    .await?;
    let interaction_id = interaction.id;

    let claim_keys = build_claim_keys(credential_config, &credential_offer.credential_subject)?;

    let credential_id: CredentialId = Uuid::new_v4().into();
    let (claims, credential_schema) = match storage_access
        .get_schema(&schema_data.id, &schema_data.r#type, organisation.id)
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?
    {
        Some(credential_schema) => {
            if credential_schema.schema_type.to_string() != schema_data.r#type {
                return Err(ExchangeProtocolError::IncorrectCredentialSchemaType);
            }

            let claims = map_offered_claims_to_credential_schema(
                &credential_schema,
                credential_id,
                &claim_keys,
            )?;

            (claims, credential_schema)
        }
        None => {
            let response = handle_invitation_operations
                .create_new_schema(
                    schema_data,
                    &claim_keys,
                    &credential_id,
                    credential_config,
                    &issuer_metadata,
                    organisation.clone(),
                )
                .await?;
            (response.claims, response.schema)
        }
    };

    let credential = create_credential(
        credential_id,
        credential_schema,
        claims,
        interaction,
        None,
        issuer_did,
    );

    Ok(InvitationResponseDTO::Credential {
        interaction_id,
        credentials: vec![credential],
        tx_code,
    })
}

async fn resolve_credential_offer(
    client: &Arc<dyn HttpClient>,
    invitation_url: Url,
) -> Result<OpenID4VCICredentialOfferDTO, ExchangeProtocolError> {
    let query_pairs: HashMap<_, _> = invitation_url.query_pairs().collect();
    let credential_offer_param = query_pairs.get(CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY);
    let credential_offer_reference_param =
        query_pairs.get(CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY);

    if credential_offer_param.is_some() && credential_offer_reference_param.is_some() {
        return Err(ExchangeProtocolError::Failed(
            format!("Detected both {CREDENTIAL_OFFER_VALUE_QUERY_PARAM_KEY} and {CREDENTIAL_OFFER_REFERENCE_QUERY_PARAM_KEY}"),
        ));
    }

    if let Some(credential_offer) = credential_offer_param {
        serde_json::from_str(credential_offer).map_err(|error| {
            ExchangeProtocolError::Failed(format!("Failed decoding credential offer {error}"))
        })
    } else if let Some(credential_offer_reference) = credential_offer_reference_param {
        let credential_offer_url = Url::parse(credential_offer_reference).map_err(|error| {
            ExchangeProtocolError::Failed(format!("Failed decoding credential offer url {error}"))
        })?;

        Ok(client
            .get(credential_offer_url.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .map_err(|error| {
                ExchangeProtocolError::Failed(format!(
                    "Failed decoding credential offer json {error}"
                ))
            })?)
    } else {
        Err(ExchangeProtocolError::Failed(
            "Missing credential offer param".to_string(),
        ))
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_proof_invitation(
    url: Url,
    allow_insecure_http_transport: bool,
    client: &Arc<dyn HttpClient>,
    storage_access: &StorageAccess,
    organisation: Option<Organisation>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    params: &OpenID4VCParams,
) -> Result<InvitationResponseDTO, ExchangeProtocolError> {
    let query = url.query().ok_or(ExchangeProtocolError::InvalidRequest(
        "Query cannot be empty".to_string(),
    ))?;

    let interaction_data = interaction_data_from_query(
        query,
        client,
        allow_insecure_http_transport,
        key_algorithm_provider,
        did_method_provider,
        params,
    )
    .await?;
    validate_interaction_data(&interaction_data)?;
    let data = serialize_interaction_data(&interaction_data)?;

    let now = OffsetDateTime::now_utc();
    let interaction = create_and_store_interaction(
        storage_access,
        interaction_data
            .response_uri
            .ok_or(ExchangeProtocolError::Failed(
                "response_uri is None".to_string(),
            ))?,
        data,
        organisation,
    )
    .await?;

    let interaction_id = interaction.id.to_owned();

    let proof_id = Uuid::new_v4().into();
    let proof = proof_from_handle_invitation(
        &proof_id,
        "OPENID4VC",
        interaction_data.redirect_uri,
        None,
        interaction,
        now,
        None,
        "HTTP",
        ProofStateEnum::Requested,
    );

    Ok(InvitationResponseDTO::ProofRequest {
        interaction_id,
        proof: Box::new(proof),
    })
}

async fn get_discovery_and_issuer_metadata(
    client: &dyn HttpClient,
    credential_issuer_endpoint: &Url,
) -> Result<
    (
        OpenID4VCIDiscoveryResponseDTO,
        OpenID4VCIIssuerMetadataResponseDTO,
    ),
    ExchangeProtocolError,
> {
    async fn fetch<T: DeserializeOwned>(
        client: &dyn HttpClient,
        endpoint: String,
    ) -> Result<T, ExchangeProtocolError> {
        client
            .get(&endpoint)
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)
    }

    let oicd_discovery = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-configuration"),
    );
    let issuer_metadata = fetch(
        client,
        format!("{credential_issuer_endpoint}/.well-known/openid-credential-issuer"),
    );
    tokio::try_join!(oicd_discovery, issuer_metadata)
}

async fn create_and_store_interaction(
    storage_access: &StorageAccess,
    credential_issuer_endpoint: Url,
    data: Vec<u8>,
    organisation: Option<Organisation>,
) -> Result<Interaction, ExchangeProtocolError> {
    let now = OffsetDateTime::now_utc();

    let interaction = interaction_from_handle_invitation(
        credential_issuer_endpoint,
        Some(data),
        now,
        organisation,
    );

    storage_access
        .create_interaction(interaction.clone())
        .await
        .map_err(ExchangeProtocolError::StorageAccessError)?;

    Ok(interaction)
}

fn build_claim_keys(
    credential_configuration: &OpenID4VCICredentialConfigurationData,
    credential_subject: &Option<ExtendedSubjectDTO>,
) -> Result<IndexMap<String, OpenID4VCICredentialValueDetails>, ExchangeProtocolError> {
    let claim_object = match (
        &credential_configuration.credential_definition,
        &credential_configuration.claims,
    ) {
        (None, None) | (Some(_), Some(_)) => {
            return Err(ExchangeProtocolError::Failed(
                "Incorrect or missing credential claims".to_string(),
            ))
        }
        (None, Some(mdoc_claims)) => &OpenID4VCICredentialSubjectItem {
            claims: Some(mdoc_claims.clone()),
            ..Default::default()
        },
        (Some(credential_definition), None) => credential_definition
            .credential_subject
            .as_ref()
            .ok_or_else(|| {
                ExchangeProtocolError::Failed("Missing credential subject".to_string())
            })?,
    };

    let keys = credential_subject
        .as_ref()
        .and_then(|cs| cs.keys.clone())
        .unwrap_or_default();

    if keys.claims.is_empty() {
        // WORKAROUND
        // Logic somewhere later expects values to be provided at this point. We don't have them for e.g. external credentials
        // hence we fulfill mandatory fields with empty values. The logic wil later be reworked to provide no claims in case
        // there is no credential definition

        let missing_keys = collect_mandatory_keys(claim_object, None);
        Ok(missing_keys
            .into_iter()
            .map(|(missing_claim_path, value_type)| {
                (
                    missing_claim_path,
                    OpenID4VCICredentialValueDetails {
                        value: "".to_owned(),
                        value_type,
                    },
                )
            })
            .collect())

        //END OF WORKAROUND
    } else {
        Ok(keys.claims)
    }
}

fn collect_mandatory_keys(
    claim_object: &OpenID4VCICredentialSubjectItem,
    item_path: Option<&str>,
) -> Vec<(String, String)> {
    let mut item_paths = Vec::new();

    if let Some(claims) = claim_object.claims.as_ref() {
        for (key, object) in claims {
            let path = if let Some(item_path) = &item_path {
                format!("{item_path}{}{key}", NESTED_CLAIM_MARKER)
            } else {
                key.to_owned()
            };
            let paths = collect_mandatory_keys(object, Some(&path));

            item_paths.extend(paths);
        }
    }

    if let Some(arrays) = claim_object.arrays.as_ref() {
        for (key, object_definitions) in arrays {
            if let Some(object_fields) = object_definitions.first() {
                let path = if let Some(item_path) = &item_path {
                    format!(
                        "{item_path}{}{key}{}0",
                        NESTED_CLAIM_MARKER, NESTED_CLAIM_MARKER
                    )
                } else {
                    format!("{key}{}0", NESTED_CLAIM_MARKER)
                };
                let paths = collect_mandatory_keys(object_fields, Some(&path));

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

pub fn build_claims_keys_for_mdoc(
    claims: &IndexMap<String, OpenID4VCICredentialOfferClaim>,
) -> IndexMap<String, OpenID4VCICredentialValueDetails> {
    fn build<'a>(
        normalized_claims: &mut IndexMap<String, OpenID4VCICredentialValueDetails>,
        claims: &'a IndexMap<String, OpenID4VCICredentialOfferClaim>,
        path: &mut Vec<&'a str>,
    ) {
        for (key, offer_claim) in claims {
            path.push(key);

            match &offer_claim.value {
                OpenID4VCICredentialOfferClaimValue::Nested(claims) => {
                    build(normalized_claims, claims, path);
                }
                OpenID4VCICredentialOfferClaimValue::String(value) => {
                    let key = path.join("/");

                    let value = OpenID4VCICredentialValueDetails {
                        value: value.to_owned(),
                        value_type: offer_claim.value_type.to_owned(),
                    };

                    normalized_claims.insert(key, value);
                }
            }

            path.pop();
        }
    }

    let mut claim_keys = IndexMap::with_capacity(claims.len());
    let mut path = vec![];

    build(&mut claim_keys, claims, &mut path);

    claim_keys
}
