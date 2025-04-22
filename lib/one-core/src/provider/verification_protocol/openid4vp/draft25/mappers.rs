use std::collections::HashMap;
use std::sync::Arc;

use shared_types::KeyId;

use super::model::OpenID4VP25AuthorizationRequestQueryParams;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPVerifierInteractionContent, OpenID4Vp25Params,
    OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::service::create_open_id_for_vp_client_metadata;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::service::key::dto::PublicKeyJwkDTO;
use crate::service::oid4vp_draft25::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::util::oidc::determine_response_mode;

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_openid4vp25_authorization_request(
    base_url: &str,
    openidvc_params: &OpenID4Vp25Params,
    client_id: String,
    interaction_id: InteractionId,
    interaction_data: &OpenID4VPVerifierInteractionContent,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<OpenID4VP25AuthorizationRequestQueryParams, VerificationProtocolError> {
    let params = if openidvc_params.use_request_uri {
        OpenID4VP25AuthorizationRequestQueryParams {
            client_id: encode_client_id_with_scheme(client_id, client_id_scheme),
            request_uri: Some(format!(
                "{base_url}/ssi/openid4vp/draft-25/{}/client-request",
                proof.id
            )),
            ..Default::default()
        }
    } else {
        match client_id_scheme {
            ClientIdScheme::RedirectUri => get_params_for_redirect_uri(
                client_id,
                interaction_id,
                nonce,
                proof,
                key_id,
                encryption_key_jwk,
                vp_formats,
                interaction_data,
            )?,
            ClientIdScheme::X509SanDns => {
                let token = generate_authorization_request_client_id_scheme_x509_san_dns(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                )
                .await?;
                return Ok(OpenID4VP25AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(client_id, ClientIdScheme::X509SanDns),
                    request: Some(token),
                    ..Default::default()
                });
            }
            ClientIdScheme::VerifierAttestation => {
                let token = generate_authorization_request_client_id_scheme_verifier_attestation(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;
                return Ok(OpenID4VP25AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(
                        client_id,
                        ClientIdScheme::VerifierAttestation,
                    ),
                    request: Some(token),
                    ..Default::default()
                });
            }
            ClientIdScheme::Did => {
                let token = generate_authorization_request_client_id_scheme_did(
                    proof,
                    interaction_data.to_owned(),
                    &interaction_id,
                    key_algorithm_provider,
                    key_provider,
                    did_method_provider,
                )
                .await?;
                return Ok(OpenID4VP25AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(client_id, ClientIdScheme::Did),
                    request: Some(token),
                    ..Default::default()
                });
            }
        }
    };

    Ok(params)
}

#[allow(clippy::too_many_arguments)]
fn get_params_for_redirect_uri(
    client_id: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    key_id: KeyId,
    encryption_key_jwk: PublicKeyJwkDTO,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<OpenID4VP25AuthorizationRequestQueryParams, VerificationProtocolError> {
    let presentation_definition = serde_json::to_string(&interaction_data.presentation_definition)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata(
        key_id,
        encryption_key_jwk,
        vp_formats,
    ))
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(OpenID4VP25AuthorizationRequestQueryParams {
        client_id: encode_client_id_with_scheme(client_id.clone(), ClientIdScheme::RedirectUri),
        response_type: Some("vp_token".to_string()),
        state: Some(interaction_id.to_string()),
        response_mode: Some(determine_response_mode(proof)?),
        client_metadata: Some(metadata),
        response_uri: Some(client_id),
        nonce: Some(nonce),
        presentation_definition: Some(presentation_definition),
        presentation_definition_uri: None,
        request: None,
        request_uri: None,
        redirect_uri: None,
    })
}

pub fn encode_client_id_with_scheme(client_id: String, client_id_scheme: ClientIdScheme) -> String {
    match client_id_scheme {
        ClientIdScheme::Did => client_id,
        _ => format!("{}:{}", client_id_scheme, client_id),
    }
}

pub fn decode_client_id_with_scheme(
    client_id: String,
) -> Result<(String, ClientIdScheme), VerificationProtocolError> {
    let (client_id_scheme, client_id) =
        client_id
            .split_once(':')
            .ok_or(VerificationProtocolError::InvalidRequest(
                "invalid client_id".to_string(),
            ))?;

    let client_id_scheme: ClientIdScheme = client_id_scheme.parse().map_err(|e| {
        VerificationProtocolError::InvalidRequest(format!("invalid client_id_scheme: {}", e))
    })?;

    let client_id = match client_id_scheme {
        ClientIdScheme::Did => client_id,
        _ => client_id,
    };

    Ok((client_id.to_string(), client_id_scheme))
}
