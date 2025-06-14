use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use super::model::{
    OpenID4VP25AuthorizationRequest, OpenID4VP25AuthorizationRequestQueryParams, OpenID4Vp25Params,
};
use crate::common_mapper::PublicKeyWithJwk;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPHolderInteractionData, OpenID4VPVerifierInteractionContent,
    OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::service::create_open_id_for_vp_client_metadata;
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
    jwk: Option<PublicKeyWithJwk>,
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
                jwk,
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
    jwk: Option<PublicKeyWithJwk>,
    vp_formats: HashMap<String, OpenID4VpPresentationFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<OpenID4VP25AuthorizationRequestQueryParams, VerificationProtocolError> {
    let presentation_definition = serde_json::to_string(&interaction_data.presentation_definition)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata(jwk, vp_formats))
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

impl TryFrom<OpenID4VP25AuthorizationRequestQueryParams> for OpenID4VP25AuthorizationRequest {
    type Error = VerificationProtocolError;

    fn try_from(
        query_params: OpenID4VP25AuthorizationRequestQueryParams,
    ) -> Result<Self, Self::Error> {
        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        let (client_id, _) = decode_client_id_with_scheme(query_params.client_id)?;

        Ok(OpenID4VP25AuthorizationRequest {
            client_id,
            state: query_params.state,
            nonce: query_params.nonce,
            response_type: query_params.response_type,
            response_mode: query_params.response_mode,
            presentation_definition_uri: query_params
                .presentation_definition_uri
                .map(|uri| {
                    uri.parse().map_err(|_| {
                        VerificationProtocolError::InvalidRequest(
                            "invalid presentation_definition_uri".to_string(),
                        )
                    })
                })
                .transpose()?,
            response_uri: query_params
                .response_uri
                .map(|uri| Url::parse(&uri))
                .transpose()
                .map_err(|_| {
                    VerificationProtocolError::InvalidRequest("invalid response_uri".to_string())
                })?,
            client_metadata: query_params.client_metadata.map(json_parse).transpose()?,
            presentation_definition: query_params
                .presentation_definition
                .map(json_parse)
                .transpose()?,
            redirect_uri: query_params.redirect_uri,
        })
    }
}

impl TryFrom<OpenID4VP25AuthorizationRequest> for OpenID4VPHolderInteractionData {
    type Error = VerificationProtocolError;

    fn try_from(value: OpenID4VP25AuthorizationRequest) -> Result<Self, Self::Error> {
        let (client_id, client_id_scheme) = decode_client_id_with_scheme(value.client_id)?;

        Ok(Self {
            client_id,
            response_type: value.response_type,
            state: value.state,
            nonce: value.nonce,
            client_id_scheme,
            client_metadata: value.client_metadata,
            client_metadata_uri: None,
            response_mode: value.response_mode,
            response_uri: value.response_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            redirect_uri: value.redirect_uri,
            verifier_did: None,
        })
    }
}
