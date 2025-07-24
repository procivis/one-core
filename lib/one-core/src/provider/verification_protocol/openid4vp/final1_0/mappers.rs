use std::collections::HashMap;
use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use super::model::{AuthorizationRequest, AuthorizationRequestQueryParams, Params};
use crate::common_mapper::PublicKeyWithJwk;
use crate::model::interaction::InteractionId;
use crate::model::proof::Proof;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks, OpenID4VPHolderInteractionData,
    OpenID4VPVerifierInteractionContent, OpenID4VpPresentationFormat,
};
use crate::service::oid4vp_final1_0::proof_request::{
    generate_authorization_request_client_id_scheme_did,
    generate_authorization_request_client_id_scheme_verifier_attestation,
    generate_authorization_request_client_id_scheme_x509_san_dns, generate_vp_formats_supported,
};
use crate::util::oidc::determine_response_mode;

pub(crate) fn create_open_id_for_vp_client_metadata_final1_0(
    jwk: Option<PublicKeyWithJwk>,
    vp_formats_supported: HashMap<String, OpenID4VpPresentationFormat>,
) -> OpenID4VPFinal1_0ClientMetadata {
    let mut metadata = OpenID4VPFinal1_0ClientMetadata {
        vp_formats_supported,
        ..Default::default()
    };
    if let Some(jwk) = jwk {
        metadata.jwks = Some(OpenID4VPClientMetadataJwks {
            keys: vec![OpenID4VPClientMetadataJwkDTO {
                key_id: jwk.key_id.to_string(),
                jwk: jwk.jwk.into(),
            }],
        });
        metadata.authorization_encrypted_response_alg =
            Some(AuthorizationEncryptedResponseAlgorithm::EcdhEs);
        metadata.authorization_encrypted_response_enc =
            Some(AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM);
    }

    metadata
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_openid4vp_final1_0_authorization_request(
    base_url: &str,
    openidvc_params: &Params,
    client_id_without_prefix: String,
    interaction_id: InteractionId,
    interaction_data: &OpenID4VPVerifierInteractionContent,
    nonce: String,
    proof: &Proof,
    jwk: Option<PublicKeyWithJwk>,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<AuthorizationRequestQueryParams, VerificationProtocolError> {
    let params = if openidvc_params.use_request_uri {
        AuthorizationRequestQueryParams {
            client_id: encode_client_id_with_scheme(client_id_without_prefix, client_id_scheme),
            request_uri: Some(format!(
                "{base_url}/ssi/openid4vp/final-1.0/{}/client-request",
                proof.id
            )),
            ..Default::default()
        }
    } else {
        match client_id_scheme {
            ClientIdScheme::RedirectUri => get_params_for_redirect_uri(
                client_id_without_prefix,
                interaction_id,
                nonce,
                proof,
                jwk,
                generate_vp_formats_supported(),
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
                return Ok(AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(
                        client_id_without_prefix,
                        ClientIdScheme::X509SanDns,
                    ),
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
                return Ok(AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(
                        client_id_without_prefix,
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
                return Ok(AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(
                        client_id_without_prefix,
                        ClientIdScheme::Did,
                    ),
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
    response_uri: String,
    interaction_id: InteractionId,
    nonce: String,
    proof: &Proof,
    jwk: Option<PublicKeyWithJwk>,
    vp_formats_supported: HashMap<String, OpenID4VpPresentationFormat>,
    interaction_data: &OpenID4VPVerifierInteractionContent,
) -> Result<AuthorizationRequestQueryParams, VerificationProtocolError> {
    if interaction_data.presentation_definition.is_some() && interaction_data.dcql_query.is_some() {
        return Err(
            VerificationProtocolError::InvalidDcqlQueryOrPresentationDefinition(
                "Either presentation_definition or dcql_query must be present".to_string(),
            ),
        );
    }

    let presentation_definition = interaction_data
        .presentation_definition
        .as_ref()
        .map(|pd| {
            serde_json::to_string(&pd).map_err(|e| VerificationProtocolError::Failed(e.to_string()))
        })
        .transpose()?;

    let dcql_query = interaction_data
        .dcql_query
        .as_ref()
        .map(|dcql| {
            serde_json::to_string(&dcql)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
        })
        .transpose()?;

    let metadata = serde_json::to_string(&create_open_id_for_vp_client_metadata_final1_0(
        jwk,
        vp_formats_supported,
    ))
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(AuthorizationRequestQueryParams {
        client_id: encode_client_id_with_scheme(response_uri.clone(), ClientIdScheme::RedirectUri),
        response_type: Some("vp_token".to_string()),
        state: Some(interaction_id.to_string()),
        response_mode: Some(determine_response_mode(proof)?),
        client_metadata: Some(metadata),
        response_uri: Some(response_uri),
        nonce: Some(nonce),
        presentation_definition,
        presentation_definition_uri: None,
        request: None,
        request_uri: None,
        redirect_uri: None,
        dcql_query,
    })
}

pub(super) fn encode_client_id_with_scheme(
    client_id_without_prefix: String,
    client_id_scheme: ClientIdScheme,
) -> String {
    match client_id_scheme {
        ClientIdScheme::Did => client_id_without_prefix,
        _ => format!("{client_id_scheme}:{client_id_without_prefix}"),
    }
}

pub(crate) fn decode_client_id_with_scheme(
    client_id: &str,
) -> Result<(String, ClientIdScheme), VerificationProtocolError> {
    let (client_id_scheme, client_id_without_prefix) =
        client_id
            .split_once(':')
            .ok_or(VerificationProtocolError::InvalidRequest(
                "invalid client_id".to_string(),
            ))?;

    let client_id_scheme: ClientIdScheme = client_id_scheme.parse().map_err(|e| {
        VerificationProtocolError::InvalidRequest(format!("invalid client_id_scheme: {e}"))
    })?;

    let client_id_without_prefix = match client_id_scheme {
        ClientIdScheme::Did => client_id,
        _ => client_id_without_prefix,
    };

    Ok((client_id_without_prefix.to_string(), client_id_scheme))
}

impl TryFrom<AuthorizationRequestQueryParams> for AuthorizationRequest {
    type Error = VerificationProtocolError;

    fn try_from(query_params: AuthorizationRequestQueryParams) -> Result<Self, Self::Error> {
        fn json_parse<T: for<'a> Deserialize<'a>>(
            input: String,
        ) -> Result<T, VerificationProtocolError> {
            serde_json::from_str(&input)
                .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))
        }

        Ok(AuthorizationRequest {
            client_id: query_params.client_id,
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
            dcql_query: query_params.dcql_query.map(json_parse).transpose()?,
        })
    }
}

impl TryFrom<AuthorizationRequest> for OpenID4VPHolderInteractionData {
    type Error = VerificationProtocolError;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        let (client_id_without_prefix, client_id_scheme) =
            decode_client_id_with_scheme(&value.client_id)?;

        let mut response_uri = value.response_uri;

        // The Verifier MAY omit the redirect_uri Authorization Request parameter (or response_uri when Response Mode direct_post is used).
        // <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3-3.1.1>
        if response_uri.is_none() && client_id_scheme == ClientIdScheme::RedirectUri {
            response_uri = Some(
                client_id_without_prefix
                    .parse::<Url>()
                    .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?,
            );
        }

        Ok(Self {
            client_id: client_id_without_prefix,
            response_type: value.response_type,
            state: value.state,
            nonce: value.nonce,
            client_id_scheme,
            client_metadata: value.client_metadata,
            client_metadata_uri: None,
            response_mode: value.response_mode,
            response_uri,
            presentation_definition: value.presentation_definition,
            presentation_definition_uri: value.presentation_definition_uri,
            dcql_query: value.dcql_query,
            redirect_uri: value.redirect_uri,
            verifier_details: None,
        })
    }
}
