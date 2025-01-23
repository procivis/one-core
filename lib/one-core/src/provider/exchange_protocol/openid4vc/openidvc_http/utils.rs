use core::str;
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::model::did::KeyRole;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, OpenID4VCParams, OpenID4VPAuthorizationRequestParams,
    OpenID4VPAuthorizationRequestQueryParams, OpenID4VPHolderInteractionData,
};
use crate::provider::exchange_protocol::openid4vc::openidvc_http::x509::extract_x5c_san_dns;
use crate::provider::exchange_protocol::openid4vc::ExchangeProtocolError;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::util::key_verification::KeyVerification;

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

fn parse_referenced_data_from_unsigned_token(
    token: String,
) -> Result<OpenID4VPHolderInteractionData, ExchangeProtocolError> {
    let DecomposedToken::<OpenID4VPAuthorizationRequestParams> { payload, .. } =
        Jwt::decompose_token(&token).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let result: OpenID4VPHolderInteractionData = payload.custom.into();
    assert!(result.verifier_did.is_none());
    Ok(result)
}

async fn parse_referenced_data_from_x509_san_dns_token(
    token: String,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    x509_ca_certificate: &str,
) -> Result<OpenID4VPHolderInteractionData, ExchangeProtocolError> {
    let request_token: DecomposedToken<OpenID4VPAuthorizationRequestParams> =
        Jwt::decompose_token(&token).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let x5c = request_token
        .header
        .x5c
        .ok_or(ExchangeProtocolError::Failed("x5c missing".to_string()))?;

    let did_value = extract_x5c_san_dns(
        &x5c,
        &request_token.payload.custom.client_id,
        x509_ca_certificate,
    )?;

    let did_document = did_method_provider
        .resolve(&did_value, None)
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let (alg, alg_id) = key_algorithm_provider
        .get_key_algorithm_from_jose_alg(&request_token.header.algorithm)
        .ok_or(ExchangeProtocolError::Failed(format!(
            "Missing algorithm: {}",
            request_token.header.algorithm
        )))?;

    let key = did_document
        .find_verification_method(None, Some(KeyRole::AssertionMethod))
        .ok_or(ExchangeProtocolError::Failed(
            "Missing key in did".to_string(),
        ))?;

    let public_key = alg
        .jwk_to_bytes(&key.public_key_jwk)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let signer = key_algorithm_provider
        .get_signer(&alg_id)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    signer
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
            &public_key,
        )
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let response_content: OpenID4VPHolderInteractionData = request_token.payload.custom.into();

    // The response_uri must match client_id
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#section-5.7-12.2.1
    if !response_content
        .response_uri
        .as_ref()
        .is_some_and(|uri| uri.domain() == Some(&response_content.client_id))
    {
        return Err(ExchangeProtocolError::Failed(
            "response_uri client_id mismatch".to_string(),
        ));
    }

    Ok(OpenID4VPHolderInteractionData {
        client_id_scheme: ClientIdSchemaType::X509SanDns,
        verifier_did: Some(did_value.to_string()),
        ..response_content
    })
}

async fn parse_referenced_data_from_verifier_attestation_token(
    token: String,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
) -> Result<OpenID4VPHolderInteractionData, ExchangeProtocolError> {
    let request_token: DecomposedToken<OpenID4VPAuthorizationRequestParams> =
        Jwt::decompose_token(&token).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let attestation_jwt = request_token
        .header
        .jwt
        .ok_or(ExchangeProtocolError::Failed(
            "attestation JWT missing".to_string(),
        ))?;

    let key_verification = Box::new(KeyVerification {
        key_algorithm_provider: key_algorithm_provider.to_owned(),
        did_method_provider: did_method_provider.to_owned(),
        key_role: KeyRole::AssertionMethod,
        cache_preferences: None,
    });

    let attestation_jwt = Jwt::<()>::build_from_token(&attestation_jwt, Some(key_verification))
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let (alg, alg_id) = key_algorithm_provider
        .get_key_algorithm_from_jose_alg(&request_token.header.algorithm)
        .ok_or(ExchangeProtocolError::Failed(format!(
            "Missing algorithm: {}",
            request_token.header.algorithm
        )))?;

    let public_key_cnf = attestation_jwt
        .payload
        .proof_of_possession_key
        .ok_or(ExchangeProtocolError::Failed(
            "missing `cnf` in attestation JWT token".to_string(),
        ))?
        .jwk
        .into();

    let public_key = alg
        .jwk_to_bytes(&public_key_cnf)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let signer = key_algorithm_provider
        .get_signer(&alg_id)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    signer
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
            &public_key,
        )
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let response_content: OpenID4VPHolderInteractionData = request_token.payload.custom.into();

    let client_id = attestation_jwt
        .payload
        .subject
        .ok_or(ExchangeProtocolError::Failed(
            "missing `sub` in attestation JWT token".to_string(),
        ))?;

    let verifier_did = attestation_jwt.payload.issuer;

    Ok(OpenID4VPHolderInteractionData {
        client_id,
        client_id_scheme: ClientIdSchemaType::VerifierAttestation,
        verifier_did,
        ..response_content
    })
}

pub(crate) async fn interaction_data_from_query(
    query: &str,
    client: &Arc<dyn HttpClient>,
    allow_insecure_http_transport: bool,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    params: &OpenID4VCParams,
) -> Result<OpenID4VPHolderInteractionData, ExchangeProtocolError> {
    let query_params: OpenID4VPAuthorizationRequestQueryParams = serde_qs::from_str(query)
        .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

    let mut request = query_params.request.to_owned();
    if let Some(request_uri) = &query_params.request_uri {
        if request.is_some() {
            return Err(ExchangeProtocolError::InvalidRequest(
                "request and request_uri cannot be set together".to_string(),
            ));
        }

        let request_uri = Url::parse(request_uri)
            .map_err(|e| ExchangeProtocolError::InvalidRequest(e.to_string()))?;

        if !allow_insecure_http_transport && request_uri.scheme() != "https" {
            return Err(ExchangeProtocolError::InvalidRequest(
                "request_uri must use HTTPS scheme".to_string(),
            ));
        }

        let token = client
            .get(request_uri.as_str())
            .header("Accept", "application/oauth-authz-req+jwt")
            .send()
            .await
            .context("Error calling request_uri")
            .and_then(|r| r.error_for_status().context("Response status error"))
            .and_then(|r| String::from_utf8(r.body).context("Invalid response"))
            .map_err(ExchangeProtocolError::Transport)?;

        request = Some(token);
    }

    if let Some(client_id_scheme) = &query_params.client_id_scheme {
        if request.is_none()
            && (client_id_scheme == &ClientIdSchemaType::VerifierAttestation
                || client_id_scheme == &ClientIdSchemaType::X509SanDns)
        {
            return Err(ExchangeProtocolError::InvalidRequest(format!(
                "request or request_uri missing for client_id_scheme {client_id_scheme}",
            )));
        }
    }

    let mut interaction_data: OpenID4VPHolderInteractionData = query_params.try_into()?;

    if let Some(token) = request {
        let referenced_params = match &interaction_data.client_id_scheme {
            ClientIdSchemaType::VerifierAttestation => {
                parse_referenced_data_from_verifier_attestation_token(
                    token,
                    key_algorithm_provider,
                    did_method_provider,
                )
                .await
            }
            ClientIdSchemaType::RedirectUri => parse_referenced_data_from_unsigned_token(token),
            ClientIdSchemaType::Did => {
                return Err(ExchangeProtocolError::InvalidRequest(
                    "did client_id_scheme not supported".to_string(),
                ));
            }
            ClientIdSchemaType::X509SanDns => {
                parse_referenced_data_from_x509_san_dns_token(
                    token,
                    key_algorithm_provider,
                    did_method_provider,
                    params.presentation.x509_ca_certificate.as_ref().ok_or(
                        ExchangeProtocolError::Failed("missing x509_ca_certificate".to_string()),
                    )?,
                )
                .await
            }
        }?;

        // client_id from the query params must match client_id inisde the token
        if referenced_params.client_id != interaction_data.client_id {
            return Err(ExchangeProtocolError::InvalidRequest(
                "cliet_id mismatch with the request token".to_string(),
            ));
        }

        // use referenced params
        interaction_data = referenced_params;
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

    Ok(interaction_data)
}

pub fn validate_interaction_data(
    interaction_data: &OpenID4VPHolderInteractionData,
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
    assert_query_param(response_type, &["vp_token"], "response_type")?;

    let response_mode =
        interaction_data
            .response_mode
            .as_ref()
            .ok_or(ExchangeProtocolError::InvalidRequest(
                "response_mode is None".to_string(),
            ))?;
    assert_query_param(
        response_mode,
        &["direct_post", "direct_post.jwt"],
        "response_mode",
    )?;

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

    if interaction_data.response_uri.is_none() {
        return Err(ExchangeProtocolError::InvalidRequest(
            "response_uri must be set".to_string(),
        ));
    }

    // If the Client Identifier scheme redirect_uri is used in conjunction with the Response Mode direct_post, and the response_uri parameter is present, the client_id value MUST be equal to the response_uri value.
    // <https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#section-6.2-9>
    if interaction_data.client_id_scheme == ClientIdSchemaType::RedirectUri
        && Some(interaction_data.client_id.as_str())
            != interaction_data
                .response_uri
                .as_ref()
                .map(|uri| uri.as_str())
    {
        return Err(ExchangeProtocolError::InvalidRequest(
            "client_id must match response_uri".to_string(),
        ));
    }

    if interaction_data.nonce.is_none() {
        return Err(ExchangeProtocolError::InvalidRequest(
            "nonce must be set".to_string(),
        ));
    }

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_values: &[&str],
    key: &str,
) -> Result<(), ExchangeProtocolError> {
    if !expected_values.contains(&value) {
        return Err(ExchangeProtocolError::InvalidRequest(format!(
            "{key} must be one of '[{}]'",
            expected_values.join(", ")
        )));
    }
    Ok(())
}
