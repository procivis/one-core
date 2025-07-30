use std::sync::Arc;

use serde::Deserialize;
use shared_types::ProofId;
use url::Url;

use super::model::{
    OpenID4VP20AuthorizationRequest, OpenID4VP20AuthorizationRequestQueryParams, OpenID4Vp20Params,
};
use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::mapper::{
    format_authorization_request_client_id_scheme_did,
    format_authorization_request_client_id_scheme_verifier_attestation,
    format_authorization_request_client_id_scheme_x509_san_dns,
};
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VPHolderInteractionData,
};

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_openidvp20_authorization_request(
    base_url: &str,
    openidvc_params: &OpenID4Vp20Params,
    client_id: String,
    proof: &Proof,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: OpenID4VP20AuthorizationRequest,
) -> Result<OpenID4VP20AuthorizationRequestQueryParams, VerificationProtocolError> {
    if openidvc_params.use_request_uri {
        Ok(OpenID4VP20AuthorizationRequestQueryParams {
            client_id,
            client_id_scheme: Some(client_id_scheme),
            request_uri: Some(format!(
                "{base_url}/ssi/openid4vp/draft-20/{}/client-request",
                proof.id
            )),
            ..Default::default()
        })
    } else {
        match client_id_scheme {
            ClientIdScheme::RedirectUri => format_params_for_redirect_uri(
                base_url,
                openidvc_params,
                &proof.id,
                authorization_request,
            ),
            ClientIdScheme::X509SanDns => {
                let token = format_authorization_request_client_id_scheme_x509_san_dns(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    authorization_request,
                )
                .await?;
                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
            ClientIdScheme::VerifierAttestation => {
                let response_uri = authorization_request
                    .response_uri
                    .as_ref()
                    .ok_or(VerificationProtocolError::Failed(
                        "missing response_uri".to_string(),
                    ))
                    .map(|url| url.to_string())?;

                let token = format_authorization_request_client_id_scheme_verifier_attestation(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    client_id.clone(),
                    response_uri,
                    authorization_request,
                )
                .await?;

                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
            ClientIdScheme::Did => {
                let token = format_authorization_request_client_id_scheme_did(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    authorization_request,
                )
                .await?;

                Ok(OpenID4VP20AuthorizationRequestQueryParams {
                    client_id,
                    request: Some(token),
                    client_id_scheme: Some(client_id_scheme),
                    ..Default::default()
                })
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn format_params_for_redirect_uri(
    base_url: &str,
    openidvc_params: &OpenID4Vp20Params,
    proof_id: &ProofId,
    authorization_request: OpenID4VP20AuthorizationRequest,
) -> Result<OpenID4VP20AuthorizationRequestQueryParams, VerificationProtocolError> {
    let mut presentation_definition = None;
    let mut presentation_definition_uri = None;

    if openidvc_params.presentation_definition_by_value {
        let pd = authorization_request.presentation_definition.ok_or(
            VerificationProtocolError::Failed("missing presentation definition".to_string()),
        )?;

        let pd = serde_json::to_string(&pd)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        presentation_definition = Some(pd);
    } else {
        presentation_definition_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{proof_id}/presentation-definition"
        ));
    }

    let mut client_metadata = None;
    let mut client_metadata_uri = None;
    if openidvc_params.client_metadata_by_value {
        let Some(metadata) = authorization_request.client_metadata else {
            return Err(VerificationProtocolError::Failed(
                "missing client_metadata".to_string(),
            ));
        };

        let metadata = serde_json::to_string(&metadata)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

        client_metadata = Some(metadata);
    } else {
        client_metadata_uri = Some(format!(
            "{base_url}/ssi/openid4vp/draft-20/{proof_id}/client-metadata"
        ));
    }

    Ok(OpenID4VP20AuthorizationRequestQueryParams {
        client_id: authorization_request.client_id.clone(),
        client_id_scheme: Some(ClientIdScheme::RedirectUri),
        response_type: authorization_request.response_type,
        state: authorization_request.state,
        response_mode: authorization_request.response_mode,
        client_metadata,
        client_metadata_uri,
        response_uri: Some(authorization_request.client_id),
        nonce: authorization_request.nonce,
        presentation_definition,
        presentation_definition_uri,
        request: None,
        request_uri: None,
        redirect_uri: None,
    })
}

impl TryFrom<OpenID4VP20AuthorizationRequestQueryParams> for OpenID4VP20AuthorizationRequest {
    type Error = VerificationProtocolError;

    fn try_from(value: OpenID4VP20AuthorizationRequestQueryParams) -> Result<Self, Self::Error> {
        let url_parse = |uri: String| {
            Url::parse(&uri).map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        };

        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        Ok(OpenID4VP20AuthorizationRequest {
            client_id: value.client_id,
            client_id_scheme: value.client_id_scheme,
            state: value.state,
            nonce: value.nonce,
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri.map(url_parse).transpose()?,
            client_metadata: value.client_metadata.map(json_parse).transpose()?,
            client_metadata_uri: value.client_metadata_uri.map(url_parse).transpose()?,
            presentation_definition: value.presentation_definition.map(json_parse).transpose()?,
            presentation_definition_uri: value
                .presentation_definition_uri
                .map(url_parse)
                .transpose()?,
            redirect_uri: value.redirect_uri,
        })
    }
}

impl From<OpenID4VP20AuthorizationRequest> for OpenID4VPHolderInteractionData {
    fn from(value: OpenID4VP20AuthorizationRequest) -> Self {
        Self {
            client_id: value.client_id,
            client_id_scheme: value
                .client_id_scheme
                .unwrap_or(ClientIdScheme::RedirectUri),
            response_type: value.response_type,
            response_mode: value.response_mode,
            response_uri: value.response_uri,
            state: value.state,
            nonce: value.nonce,
            client_metadata: value.client_metadata,
            client_metadata_uri: value.client_metadata_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            dcql_query: None,
            redirect_uri: value.redirect_uri,
            verifier_details: None,
        }
    }
}
