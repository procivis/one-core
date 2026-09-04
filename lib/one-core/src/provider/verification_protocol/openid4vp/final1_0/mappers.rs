use std::sync::Arc;

use serde::Deserialize;
use standardized_types::iana::EncryptionAlgorithm;
use standardized_types::jwk::{Jwks, PublicJwk};
use standardized_types::openid4vp::{
    AuthorizationRequest, AuthorizationRequestQueryParams, ClientIdPrefix, ClientMetadata,
};
use url::Url;

use super::model::Params;
use crate::model::proof::Proof;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::mapper::{
    format_authorization_request_client_id_scheme_did,
    format_authorization_request_client_id_scheme_verifier_attestation,
    format_authorization_request_client_id_scheme_x509,
};
use crate::provider::verification_protocol::openid4vp::model::{
    CommonVerifierInteractionContent, HolderTxData, OpenID4VPHolderInteractionData,
    TransactionDataRequest,
};
use crate::service::oid4vp_final1_0::proof_request::generate_vp_formats_supported;

pub(crate) fn create_open_id_for_vp_client_metadata_final1_0(
    key_agreement_key: Option<PublicJwk>,
    supported_encryption_algorithms: Vec<EncryptionAlgorithm>,
) -> Result<ClientMetadata, VerificationProtocolError> {
    let vp_formats_supported = generate_vp_formats_supported();

    let mut metadata = ClientMetadata {
        vp_formats_supported,
        ..Default::default()
    };

    if let Some(key_agreement_key) = key_agreement_key
        && !supported_encryption_algorithms.is_empty()
    {
        metadata.jwks = Some(Jwks {
            keys: vec![key_agreement_key],
        });
        metadata.encrypted_response_enc_values_supported = Some(supported_encryption_algorithms);
    }

    Ok(metadata)
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn create_openid4vp_final1_0_authorization_request(
    base_url: &str,
    openidvc_params: &Params,
    client_id_without_prefix: String,
    proof: &Proof,
    client_id_scheme: ClientIdPrefix,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    authorization_request: AuthorizationRequest,
) -> Result<AuthorizationRequestQueryParams, VerificationProtocolError> {
    let params = if openidvc_params.use_request_uri {
        AuthorizationRequestQueryParams {
            client_id: encode_client_id_with_scheme(
                client_id_without_prefix,
                client_id_scheme,
                openidvc_params.use_legacy_did_client_id_scheme,
            ),
            request_uri: Some(format!(
                "{base_url}/ssi/openid4vp/final-1.0/{}/client-request",
                proof.id
            )),
            ..Default::default()
        }
    } else {
        match client_id_scheme {
            ClientIdPrefix::RedirectUri => format_params_for_redirect_uri(authorization_request)?,
            ClientIdPrefix::X509SanDns | ClientIdPrefix::X509Hash => {
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
                        openidvc_params.use_legacy_did_client_id_scheme,
                    ),
                    request: Some(token),
                    ..Default::default()
                });
            }
            ClientIdPrefix::VerifierAttestation => {
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
                        ClientIdPrefix::VerifierAttestation,
                        openidvc_params.use_legacy_did_client_id_scheme,
                    ),
                    request: Some(token),
                    ..Default::default()
                });
            }
            ClientIdPrefix::DecentralizedIdentifier => {
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
                        ClientIdPrefix::DecentralizedIdentifier,
                        openidvc_params.use_legacy_did_client_id_scheme,
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
    let dcql_query = serde_json::to_string(&authorization_request.dcql_query)?;
    let metadata = serde_json::to_string(&authorization_request.client_metadata)?;

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
        ..Default::default()
    })
}

pub(crate) fn encode_client_id_with_scheme(
    client_id_without_prefix: String,
    client_id_scheme: ClientIdPrefix,
    use_legacy_did_client_id_scheme: bool,
) -> String {
    match client_id_scheme {
        // In version 1.0, the "did" client_id_scheme was renamed to "decentralized_identifier".
        ClientIdPrefix::DecentralizedIdentifier if use_legacy_did_client_id_scheme => {
            client_id_without_prefix
        }
        _ => format!("{client_id_scheme}:{client_id_without_prefix}"),
    }
}

pub(crate) fn decode_client_id_with_scheme(
    client_id: &str,
    allow_legacy_did_scheme: bool,
) -> Result<(String, ClientIdPrefix), VerificationProtocolError> {
    let (client_id_scheme, client_id_without_prefix) =
        client_id
            .split_once(':')
            .ok_or(VerificationProtocolError::InvalidRequest(
                "invalid client_id".to_string(),
            ))?;

    // In version 1.0, the "did" client_id_scheme was renamed to "decentralized_identifier".
    if client_id_scheme == "did" {
        if allow_legacy_did_scheme {
            return Ok((
                client_id.to_string(),
                ClientIdPrefix::DecentralizedIdentifier,
            ));
        }
        return Err(VerificationProtocolError::InvalidRequest(
            "did is not a valid client_id_scheme".to_string(),
        ));
    }

    let client_id_scheme = client_id_scheme.parse().map_err(|e| {
        VerificationProtocolError::InvalidRequest(format!("invalid client_id_scheme: {e}"))
    })?;

    Ok((client_id_without_prefix.to_string(), client_id_scheme))
}

/// Reassembles an unsigned Authorization Request that was passed entirely in the URL query string.
pub(crate) fn authorization_request_from_query_params(
    query_params: AuthorizationRequestQueryParams,
) -> Result<AuthorizationRequest, VerificationProtocolError> {
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
        dcql_query: query_params.dcql_query.map(json_parse).transpose()?.ok_or(
            VerificationProtocolError::InvalidRequest("missing dcql query".to_string()),
        )?,
        // `verifier_info` can only be conveyed in a signed request object
        verifier_info: vec![],
        transaction_data: query_params.transaction_data.unwrap_or_default(),
    })
}

impl TryFrom<AuthorizationRequest> for OpenID4VPHolderInteractionData {
    type Error = VerificationProtocolError;

    fn try_from(value: AuthorizationRequest) -> Result<Self, Self::Error> {
        let (client_id_without_prefix, client_id_scheme) =
            decode_client_id_with_scheme(&value.client_id, true)?;

        let mut response_uri = value.response_uri;

        // The Verifier MAY omit the redirect_uri Authorization Request parameter (or response_uri when Response Mode direct_post is used).
        // <https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3-3.1.1>
        if response_uri.is_none() && client_id_scheme == ClientIdPrefix::RedirectUri {
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
            dcql_query: value.dcql_query,
            transaction_data: HolderTxData::Unvalidated(value.transaction_data),
            redirect_uri: value.redirect_uri,
            verifier_details: None,
            verifier_info: value.verifier_info,
        })
    }
}

pub(super) async fn transaction_data_from_interaction(
    proof: &Proof,
) -> Result<Vec<TransactionDataRequest>, VerificationProtocolError> {
    let Some(interaction) = &proof.interaction else {
        return Ok(vec![]);
    };
    let interaction = interaction.as_ref().await?;
    let Some(data) = &interaction.data else {
        return Err(VerificationProtocolError::Failed(
            "missing interaction data".to_string(),
        ));
    };
    let data = serde_json::from_slice::<CommonVerifierInteractionContent>(data)?;
    Ok(data.transaction_data)
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_decode_client_id_with_decentralized_identifier_scheme() {
        let client_id = "decentralized_identifier:did:example:123";
        let (client_id_without_prefix, client_id_scheme) =
            decode_client_id_with_scheme(client_id, false).unwrap();
        assert_eq!(client_id_without_prefix, "did:example:123");
        assert_eq!(client_id_scheme, ClientIdPrefix::DecentralizedIdentifier);
    }

    #[test]
    fn test_decode_client_id_with_did_scheme_fails() {
        let client_id = "did:example:123";
        let result = decode_client_id_with_scheme(client_id, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_client_id_with_did_scheme_legacy_succeeds() {
        let client_id = "did:example:123";
        let (client_id_without_prefix, client_id_scheme) =
            decode_client_id_with_scheme(client_id, true).unwrap();
        assert_eq!(client_id_without_prefix, "did:example:123");
        assert_eq!(client_id_scheme, ClientIdPrefix::DecentralizedIdentifier);
    }

    #[test]
    fn test_encode_client_id_with_decentralized_identifier_scheme() {
        let expected_client_id = "decentralized_identifier:did:example:123";
        let client_id = "did:example:123";
        let client_id_scheme = ClientIdPrefix::DecentralizedIdentifier;
        let encoded_client_id =
            encode_client_id_with_scheme(client_id.to_string(), client_id_scheme, false);
        assert_eq!(expected_client_id, encoded_client_id);
    }
}
