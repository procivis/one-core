use core::str;
use std::sync::Arc;

use anyhow::Context;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::exchange_protocol::openid4vc::model::{
    OpenID4VPInteractionData, OpenID4VPRequestDataResponse,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_http::ClientIdSchemaType;
use crate::provider::exchange_protocol::openid4vc::ExchangeProtocolError;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

pub fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<Vec<u8>>,
) -> Result<DataDTO, ExchangeProtocolError> {
    let data = data.as_ref().ok_or(ExchangeProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(ExchangeProtocolError::JsonError)
}

pub fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, ExchangeProtocolError> {
    serde_json::to_vec(&dto).map_err(ExchangeProtocolError::JsonError)
}

pub async fn interaction_data_from_client_request(
    client: &Arc<dyn HttpClient>,
    request_uri: &str,
    _allow_insecure_http_transport: bool,
) -> Result<OpenID4VPInteractionData, ExchangeProtocolError> {
    let token = client
        .get(request_uri)
        .send()
        .await
        .context("Error calling request_uri")
        .and_then(|r| r.error_for_status().context("Response status error"))
        .and_then(|r| String::from_utf8(r.body).context("Invalid response"))
        .map_err(ExchangeProtocolError::Transport)?;

    let Some(index) = token.find('.') else {
        return Err(ExchangeProtocolError::Failed("Invalid JWT".to_string()));
    };

    Base64UrlSafeNoPadding::decode_to_vec(&token[index + 1..], None)
        .context("Failed base64 decoding payload")
        .and_then(|p| {
            serde_json::from_str(&String::from_utf8_lossy(&p)).context("Invalid JWT payload")
        })
        .map_err(|error| ExchangeProtocolError::Failed(error.to_string()))
}

pub async fn interaction_data_from_query(
    query: &str,
    client: &Arc<dyn HttpClient>,
    allow_insecure_http_transport: bool,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<OpenID4VPInteractionData, ExchangeProtocolError> {
    let mut interaction_data: OpenID4VPInteractionData = serde_qs::from_str(query)
        .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

    let is_verifier_attestation =
        interaction_data.client_id_scheme == ClientIdSchemaType::VerifierAttestation;

    if !is_verifier_attestation {
        if interaction_data.nonce.is_none() {
            return Err(ExchangeProtocolError::InvalidRequest(
                "nonce must be set".to_string(),
            ));
        }
        if interaction_data.response_mode.is_none() {
            return Err(ExchangeProtocolError::InvalidRequest(
                "response_mode must be set".to_string(),
            ));
        }
        if interaction_data.response_type.is_none() {
            return Err(ExchangeProtocolError::InvalidRequest(
                "response_type must be set".to_string(),
            ));
        }
        if interaction_data.response_uri.is_none() {
            return Err(ExchangeProtocolError::InvalidRequest(
                "response_uri must be set".to_string(),
            ));
        }
    }

    if interaction_data.client_metadata.is_some() && interaction_data.client_metadata_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata and client_metadata_uri cannot be set together".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some()
        && interaction_data.presentation_definition_uri.is_some()
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(client_metadata_uri) = &interaction_data.client_metadata_uri {
        if !allow_insecure_http_transport && client_metadata_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "client_metadata_uri must use HTTPS scheme".to_string(),
            ));
        }

        let client_metadata = client
            .get(client_metadata_uri.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.client_metadata = Some(client_metadata);
    }

    if let Some(presentation_definition_uri) = &interaction_data.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.as_str())
            .send()
            .await
            .context("send error")
            .map_err(ExchangeProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(ExchangeProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(ExchangeProtocolError::Transport)?;

        interaction_data.presentation_definition = Some(presentation_definition);
    }

    if is_verifier_attestation {
        let request_uri =
            interaction_data
                .request_uri
                .as_ref()
                .ok_or(ExchangeProtocolError::Failed(
                    "Missing request_uri for verifier_attestation scheme type".to_string(),
                ))?;

        let token = String::from_utf8(
            client
                .get(request_uri.as_str())
                .send()
                .await
                .context("send error")
                .map_err(ExchangeProtocolError::Transport)?
                .error_for_status()
                .context("status error")
                .map_err(ExchangeProtocolError::Transport)?
                .body,
        )
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let decomposed_token: DecomposedToken<OpenID4VPRequestDataResponse> =
            Jwt::decompose_token(&token)
                .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let alg = key_algorithm_provider
            .get_key_algorithm(&decomposed_token.header.algorithm)
            .ok_or(ExchangeProtocolError::Failed(format!(
                "Missing algorithm: {}",
                decomposed_token.header.algorithm
            )))?;

        let public_key = alg
            .jwk_to_bytes(
                &decomposed_token
                    .payload
                    .proof_of_possession_key
                    .ok_or(ExchangeProtocolError::Failed(
                        "missing `cnf` in JWT token".to_string(),
                    ))?
                    .jwk
                    .into(),
            )
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        let signer = key_algorithm_provider
            .get_signer(&decomposed_token.header.algorithm)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        signer
            .verify(
                decomposed_token.unverified_jwt.as_bytes(),
                &decomposed_token.signature,
                &public_key,
            )
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

        interaction_data.nonce = decomposed_token.payload.custom.nonce;
        interaction_data.response_uri = decomposed_token
            .payload
            .custom
            .redirect_uri
            .map(|value| {
                Url::parse(&value).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
            })
            .transpose()?;
        interaction_data.response_mode = Some("direct_post".to_string());
        interaction_data.response_type = Some("vp_token".to_string());
        interaction_data.client_metadata = Some(decomposed_token.payload.custom.client_metadata);
        interaction_data.state = Some(
            decomposed_token
                .payload
                .custom
                .presentation_definition
                .id
                .to_string(),
        );
        interaction_data.presentation_definition =
            Some(decomposed_token.payload.custom.presentation_definition);
    }

    Ok(interaction_data)
}

pub fn validate_interaction_data(
    interaction_data: &OpenID4VPInteractionData,
) -> Result<(), ExchangeProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(ExchangeProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }
    let response_type =
        interaction_data
            .response_type
            .as_ref()
            .ok_or(ExchangeProtocolError::InvalidRequest(
                "response_type is None".to_string(),
            ))?;
    assert_query_param(response_type, "vp_token", "response_type")?;

    let response_mode =
        interaction_data
            .response_mode
            .as_ref()
            .ok_or(ExchangeProtocolError::InvalidRequest(
                "response_mode is None".to_string(),
            ))?;
    assert_query_param(response_mode, "direct_post", "response_mode")?;

    let client_metadata =
        interaction_data
            .client_metadata
            .as_ref()
            .ok_or(ExchangeProtocolError::Failed(
                "client_metadata is None".to_string(),
            ))?;

    if client_metadata.client_id_scheme != interaction_data.client_id_scheme {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.client_id_scheme must match client_scheme".to_string(),
        ));
    }

    match client_metadata.vp_formats.get("jwt_vp_json") {
        None => Err(ExchangeProtocolError::InvalidRequest(
            "client_metadata.vp_formats must contain 'jwt_vp_json'".to_string(),
        )),
        Some(jwt_vp_json) => {
            if jwt_vp_json.alg.contains(&"EdDSA".to_string()) {
                Ok(())
            } else {
                Err(ExchangeProtocolError::InvalidRequest(
                    "client_metadata.vp_formats[\"jwt_vp_json\"] must contain 'EdDSA' algorithm"
                        .to_string(),
                ))
            }
        }
    }?;

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_value: &str,
    key: &str,
) -> Result<(), ExchangeProtocolError> {
    if value != expected_value {
        return Err(ExchangeProtocolError::InvalidRequest(format!(
            "{key} must be '{expected_value}'"
        )));
    }
    Ok(())
}
