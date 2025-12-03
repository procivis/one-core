use std::sync::Arc;

use serde::Deserialize;
use url::Url;

use super::model::{AuthorizationRequest, AuthorizationRequestQueryParams, Params};
use crate::mapper::PublicKeyWithJwk;
use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::model::OpenID4VPFinal1_0ClientMetadata;
use crate::provider::verification_protocol::openid4vp::mapper::{
    format_authorization_request_client_id_scheme_did,
    format_authorization_request_client_id_scheme_verifier_attestation,
    format_authorization_request_client_id_scheme_x509,
};
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    OpenID4VPClientMetadataJwkDTO, OpenID4VPClientMetadataJwks, OpenID4VPHolderInteractionData,
};
use crate::service::oid4vp_final1_0::proof_request::generate_vp_formats_supported;

pub(crate) fn create_open_id_for_vp_client_metadata_final1_0(
    key_agreement_key: Option<PublicKeyWithJwk>,
) -> Result<OpenID4VPFinal1_0ClientMetadata, VerificationProtocolError> {
    let vp_formats_supported = generate_vp_formats_supported();

    let mut metadata = OpenID4VPFinal1_0ClientMetadata {
        vp_formats_supported,
        ..Default::default()
    };

    if let Some(key_agreement_key) = key_agreement_key {
        metadata.jwks = Some(OpenID4VPClientMetadataJwks {
            keys: vec![OpenID4VPClientMetadataJwkDTO {
                key_id: key_agreement_key.key_id.to_string(),
                jwk: key_agreement_key.jwk.into(),
            }],
        });
        metadata.encrypted_response_enc_values_supported = Some(vec![
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A256GCM,
            AuthorizationEncryptedResponseContentEncryptionAlgorithm::A128CBCHS256,
        ]);
    }

    Ok(metadata)
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn create_openid4vp_final1_0_authorization_request(
    base_url: &str,
    openidvc_params: &Params,
    client_id_without_prefix: String,
    proof: &Proof,
    client_id_scheme: ClientIdScheme,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: AuthorizationRequest,
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
            ClientIdScheme::RedirectUri => format_params_for_redirect_uri(authorization_request)?,
            ClientIdScheme::X509SanDns | ClientIdScheme::X509Hash => {
                let token = format_authorization_request_client_id_scheme_x509(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    authorization_request,
                )
                .await?;
                return Ok(AuthorizationRequestQueryParams {
                    client_id: encode_client_id_with_scheme(
                        client_id_without_prefix,
                        client_id_scheme,
                    ),
                    request: Some(token),
                    ..Default::default()
                });
            }
            ClientIdScheme::VerifierAttestation => {
                let response_uri = authorization_request
                    .response_uri
                    .as_ref()
                    .ok_or(VerificationProtocolError::Failed(
                        "missing client_id".to_string(),
                    ))
                    .map(|url| url.to_string())?;

                let token = format_authorization_request_client_id_scheme_verifier_attestation(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    client_id_without_prefix.clone(),
                    response_uri,
                    authorization_request,
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
                let token = format_authorization_request_client_id_scheme_did(
                    proof,
                    key_algorithm_provider,
                    key_provider,
                    authorization_request,
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

fn format_params_for_redirect_uri(
    authorization_request: AuthorizationRequest,
) -> Result<AuthorizationRequestQueryParams, VerificationProtocolError> {
    let Some(dcql_query) = authorization_request.dcql_query else {
        return Err(VerificationProtocolError::Failed(
            "dcql_query is None".to_string(),
        ));
    };

    let dcql_query = serde_json::to_string(&dcql_query)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let metadata = serde_json::to_string(&authorization_request.client_metadata)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(AuthorizationRequestQueryParams {
        client_id: authorization_request.client_id,
        state: authorization_request.state,
        nonce: authorization_request.nonce,
        response_type: authorization_request.response_type,
        response_mode: authorization_request.response_mode,
        response_uri: Some(
            authorization_request
                .response_uri
                .ok_or(VerificationProtocolError::Failed(
                    "response_uri missing".to_string(),
                ))?
                .to_string(),
        ),
        client_metadata: Some(metadata),
        dcql_query: Some(dcql_query),
        request: None,
        request_uri: None,
        redirect_uri: None,
    })
}

pub(crate) fn encode_client_id_with_scheme(
    client_id_without_prefix: String,
    client_id_scheme: ClientIdScheme,
) -> String {
    match client_id_scheme {
        ClientIdScheme::Did => format!("decentralized_identifier:{client_id_without_prefix}"),
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

    // In version 1.0, the "did" client_id_scheme was renamed to "decentralized_identifier".
    if client_id_scheme == "did" {
        return Err(VerificationProtocolError::InvalidRequest(
            "did is not a valid client_id_scheme".to_string(),
        ));
    }

    let client_id_scheme = match client_id_scheme {
        "decentralized_identifier" => ClientIdScheme::Did,
        _ => client_id_scheme.parse().map_err(|e| {
            VerificationProtocolError::InvalidRequest(format!("invalid client_id_scheme: {e}"))
        })?,
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
            response_uri: query_params
                .response_uri
                .map(|uri| Url::parse(&uri))
                .transpose()
                .map_err(|_| {
                    VerificationProtocolError::InvalidRequest("invalid response_uri".to_string())
                })?,
            client_metadata: query_params.client_metadata.map(json_parse).transpose()?,
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
            presentation_definition: None,
            presentation_definition_uri: None,
            dcql_query: value.dcql_query,
            redirect_uri: value.redirect_uri,
            verifier_details: None,
        })
    }
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_decode_client_id_with_decentralized_identifier_scheme() {
        let client_id = "decentralized_identifier:did:example:123";
        let (client_id_without_prefix, client_id_scheme) =
            decode_client_id_with_scheme(client_id).unwrap();
        assert_eq!(client_id_without_prefix, "did:example:123");
        assert_eq!(client_id_scheme, ClientIdScheme::Did);
    }

    #[test]
    fn test_decode_client_id_with_did_scheme_fails() {
        let client_id = "did:example:123";
        let result = decode_client_id_with_scheme(client_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_client_id_with_decentralized_identifier_scheme() {
        let expected_client_id = "decentralized_identifier:did:example:123";
        let client_id = "did:example:123";
        let client_id_scheme = ClientIdScheme::Did;
        let encoded_client_id =
            encode_client_id_with_scheme(client_id.to_string(), client_id_scheme);
        assert_eq!(expected_client_id, encoded_client_id);
    }
}
