use core::str;
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use url::Url;

use super::mappers::decode_client_id_with_scheme;
use super::model::{
    OpenID4VP25AuthorizationRequest, OpenID4VP25AuthorizationRequestQueryParams, OpenID4Vp25Params,
};
use crate::model::did::KeyRole;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::jwt::model::DecomposedToken;
use crate::provider::credential_formatter::model::TokenVerifier;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::http_client::HttpClient;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCVerifierAttestationPayload, OpenID4VPHolderInteractionData,
    OpenID4VPHolderInteractionDataVerifierCertificate, OpenID4VpPresentationFormat,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_against_redirect_uris, validate_san_dns_matching_client_id,
};
use crate::service::certificate::validator::{CertificateValidator, ParsedCertificate};
use crate::util::key_verification::KeyVerification;
use crate::util::x509::{is_dns_name_matching, x5c_into_pem_chain};

pub(crate) fn deserialize_interaction_data<DataDTO: for<'a> Deserialize<'a>>(
    data: Option<Vec<u8>>,
) -> Result<DataDTO, VerificationProtocolError> {
    let data = data.as_ref().ok_or(VerificationProtocolError::Failed(
        "interaction data is missing".to_string(),
    ))?;
    serde_json::from_slice(data).map_err(VerificationProtocolError::JsonError)
}

pub(crate) fn serialize_interaction_data<DataDTO: ?Sized + Serialize>(
    dto: &DataDTO,
) -> Result<Vec<u8>, VerificationProtocolError> {
    serde_json::to_vec(&dto).map_err(VerificationProtocolError::JsonError)
}

async fn parse_referenced_data_from_x509_san_dns_token(
    request_token: DecomposedToken<OpenID4VP25AuthorizationRequest>,
    certificate_validator: &Arc<dyn CertificateValidator>,
) -> Result<
    (
        OpenID4VP25AuthorizationRequest,
        OpenID4VPHolderInteractionDataVerifierCertificate,
    ),
    VerificationProtocolError,
> {
    let x5c = request_token
        .header
        .x5c
        .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

    let (client_id, _) =
        decode_client_id_with_scheme(request_token.payload.custom.client_id.clone())?;

    let pem_chain = x5c_into_pem_chain(&x5c)
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

    let ParsedCertificate {
        public_key,
        attributes,
        ..
    } = certificate_validator
        .parse_pem_chain(pem_chain.as_bytes(), true)
        .await
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

    public_key
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "Signature key missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    // x509 SAN must match client_id
    validate_san_dns_matching_client_id(&attributes, &client_id)?;

    // The response_uri must match client_id
    // https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#section-5.7-12.2.1
    if request_token
        .payload
        .custom
        .response_uri
        .as_ref()
        .is_none_or(|response_uri| {
            !response_uri.domain().is_some_and(|response_domain| {
                client_id == response_domain
                    || is_dns_name_matching(&format!("*.{client_id}"), response_domain)
            })
        })
    {
        return Err(VerificationProtocolError::Failed(
            "response_uri client_id mismatch".to_string(),
        ));
    }

    Ok((
        request_token.payload.custom,
        OpenID4VPHolderInteractionDataVerifierCertificate {
            chain: pem_chain,
            fingerprint: attributes.fingerprint,
        },
    ))
}

async fn parse_referenced_data_from_did_signed_token(
    request_token: DecomposedToken<OpenID4VP25AuthorizationRequest>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
) -> Result<(OpenID4VP25AuthorizationRequest, DidValue), VerificationProtocolError> {
    let client_id = request_token.payload.custom.client_id.clone();

    let Some(kid) = request_token.header.key_id.clone() else {
        return Err(VerificationProtocolError::Failed(
            "JOSE header missing kid".to_string(),
        ));
    };

    let verifier_did = client_id.clone().parse().map_err(|_| {
        VerificationProtocolError::Failed("client_id is not a valid DID".to_string())
    })?;

    let did_document = did_method_provider
        .resolve(&verifier_did)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let (_alg_id, alg) = key_algorithm_provider
        .key_algorithm_from_jose_alg(&request_token.header.algorithm)
        .ok_or(VerificationProtocolError::Failed(format!(
            "Missing algorithm: {}",
            request_token.header.algorithm
        )))?;

    let key = did_document
        .find_verification_method(Some(&kid), Some(KeyRole::AssertionMethod))
        .ok_or(VerificationProtocolError::Failed(
            "Missing key in did".to_string(),
        ))?
        .public_key_jwk
        .clone();

    alg.parse_jwk(&key)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "signature missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok((request_token.payload.custom, verifier_did))
}

async fn parse_referenced_data_from_verifier_attestation_token(
    request_token: DecomposedToken<OpenID4VP25AuthorizationRequest>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
) -> Result<(OpenID4VP25AuthorizationRequest, Option<String>), VerificationProtocolError> {
    let attestation_jwt = request_token
        .header
        .jwt
        .ok_or(VerificationProtocolError::Failed(
            "attestation JWT missing".to_string(),
        ))?;

    let key_verification: Box<dyn TokenVerifier> = Box::new(KeyVerification {
        key_algorithm_provider: key_algorithm_provider.to_owned(),
        did_method_provider: did_method_provider.to_owned(),
        key_role: KeyRole::AssertionMethod,
        certificate_validator: certificate_validator.to_owned(),
    });

    /*
     * TODO(ONE-3846): this should be created by some trusted entity, not by current verifier.
     *     Key verification function should only allow trusted entity keys
     */
    let attestation_jwt = Jwt::<OpenID4VCVerifierAttestationPayload>::build_from_token(
        &attestation_jwt,
        Some(&key_verification),
        None,
    )
    .await
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let (_alg_id, alg) = key_algorithm_provider
        .key_algorithm_from_jose_alg(&request_token.header.algorithm)
        .ok_or(VerificationProtocolError::Failed(format!(
            "Missing algorithm: {}",
            request_token.header.algorithm
        )))?;

    let public_key_cnf = attestation_jwt
        .payload
        .proof_of_possession_key
        .ok_or(VerificationProtocolError::Failed(
            "missing `cnf` in attestation JWT token".to_string(),
        ))?
        .jwk
        .jwk()
        .to_owned()
        .into();

    alg.parse_jwk(&public_key_cnf)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .signature()
        .ok_or(VerificationProtocolError::Failed(
            "Signature key missing".to_string(),
        ))?
        .public()
        .verify(
            request_token.unverified_jwt.as_bytes(),
            &request_token.signature,
        )
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    validate_against_redirect_uris(
        &attestation_jwt.payload.custom.redirect_uris,
        request_token.payload.custom.redirect_uri.as_deref(),
    )?;
    validate_against_redirect_uris(
        &attestation_jwt.payload.custom.redirect_uris,
        request_token
            .payload
            .custom
            .response_uri
            .as_ref()
            .map(|url| url.as_str()),
    )?;

    let client_id = attestation_jwt
        .payload
        .subject
        .ok_or(VerificationProtocolError::Failed(
            "missing `sub` in attestation JWT token".to_string(),
        ))?;

    Ok((
        OpenID4VP25AuthorizationRequest {
            client_id,
            ..request_token.payload.custom
        },
        attestation_jwt.payload.issuer,
    ))
}

async fn retrieve_authorization_params_by_reference(
    query_params: OpenID4VP25AuthorizationRequestQueryParams,
    url: Url,
    client: &Arc<dyn HttpClient>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    params: &OpenID4Vp25Params,
) -> Result<
    (
        OpenID4VP25AuthorizationRequest,
        Option<String>,
        Option<OpenID4VPHolderInteractionDataVerifierCertificate>,
    ),
    VerificationProtocolError,
> {
    let token = client
        .get(url.as_str())
        .header("Accept", "application/oauth-authz-req+jwt")
        .send()
        .await
        .context("Error calling request_uri")
        .and_then(|r| r.error_for_status().context("Response status error"))
        .and_then(|r| String::from_utf8(r.body).context("Invalid response"))
        .map_err(VerificationProtocolError::Transport)?;

    let request_token: DecomposedToken<OpenID4VP25AuthorizationRequest> =
        Jwt::decompose_token(&token)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    if let Some(audience) = &request_token.payload.audience {
        if audience.len() != 1 {
            tracing::warn!("Invalid `aud` claim, {} items", audience.len());
        } else {
            let aud = audience.first();
            if aud != Some(&"https://self-issued.me/v2".to_string()) {
                tracing::warn!("Invalid `aud` claim: {aud:?}");
            }
        }
    } else {
        tracing::warn!("`aud` claim missing in request JWT payload");
    }

    let (_, client_id_scheme) =
        decode_client_id_with_scheme(request_token.payload.custom.client_id.clone())?;

    if !params
        .holder
        .supported_client_id_schemes
        .contains(&client_id_scheme)
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "Unsupported client_id_scheme".into(),
        ));
    }

    let (referenced_params, verifier_did, verifier_certificate): (
        OpenID4VP25AuthorizationRequest,
        Option<String>,
        Option<OpenID4VPHolderInteractionDataVerifierCertificate>,
    ) = match client_id_scheme {
        ClientIdScheme::VerifierAttestation => {
            let (request, did) = parse_referenced_data_from_verifier_attestation_token(
                request_token,
                key_algorithm_provider,
                did_method_provider,
                certificate_validator,
            )
            .await?;
            (request, did, None)
        }
        ClientIdScheme::RedirectUri => (request_token.payload.custom, None, None),
        ClientIdScheme::X509SanDns => {
            let (params, certificate) =
                parse_referenced_data_from_x509_san_dns_token(request_token, certificate_validator)
                    .await?;
            (params, None, Some(certificate))
        }
        ClientIdScheme::Did => {
            let (request, did) = parse_referenced_data_from_did_signed_token(
                request_token,
                key_algorithm_provider,
                did_method_provider,
            )
            .await?;
            (request, Some(did.to_string()), None)
        }
    };

    // client_id from the query params must match client_id inisde the token
    if referenced_params.client_id != query_params.client_id {
        return Err(VerificationProtocolError::InvalidRequest(
            "client_id mismatch with the request token".to_string(),
        ));
    }

    Ok((referenced_params, verifier_did, verifier_certificate))
}

pub(crate) async fn interaction_data_from_openid4vp_25_query(
    query: &str,
    client: &Arc<dyn HttpClient>,
    allow_insecure_http_transport: bool,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    params: &OpenID4Vp25Params,
) -> Result<
    (
        OpenID4VP25AuthorizationRequest,
        Option<String>,
        Option<OpenID4VPHolderInteractionDataVerifierCertificate>,
    ),
    VerificationProtocolError,
> {
    let query_params: OpenID4VP25AuthorizationRequestQueryParams = serde_qs::from_str(query)
        .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

    let (mut authorization_request, verifier_did, verifier_certificate) =
        match (&query_params.request_uri, &query_params.request) {
            (Some(_), Some(_)) => {
                return Err(VerificationProtocolError::InvalidRequest(
                    "request and request_uri cannot be set together".to_string(),
                ));
            }
            (Some(request_uri), None) => {
                let request_uri = Url::parse(request_uri)
                    .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

                if !allow_insecure_http_transport && request_uri.scheme() != "https" {
                    return Err(VerificationProtocolError::InvalidRequest(
                        "request_uri must use HTTPS scheme".to_string(),
                    ));
                }

                Ok(retrieve_authorization_params_by_reference(
                    query_params,
                    request_uri,
                    client,
                    did_method_provider,
                    key_algorithm_provider,
                    certificate_validator,
                    params,
                )
                .await?)
            }
            (None, Some(request)) => {
                let authorization_request = serde_json::from_str(request).map_err(|e| {
                    VerificationProtocolError::InvalidRequest(format!(
                        "Failed to parse request: {e}"
                    ))
                })?;
                Ok((authorization_request, None, None))
            }
            (None, None) => {
                return Err(VerificationProtocolError::InvalidRequest(
                    "request or request_uri is required".to_string(),
                ));
            }
        }?;

    if authorization_request.presentation_definition.is_some()
        && authorization_request.presentation_definition_uri.is_some()
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "presentation_definition and presentation_definition_uri cannot be set together"
                .to_string(),
        ));
    }

    if let Some(presentation_definition_uri) = &authorization_request.presentation_definition_uri {
        if !allow_insecure_http_transport && presentation_definition_uri.scheme() != "https" {
            return Err(VerificationProtocolError::InvalidRequest(
                "presentation_definition_uri must use HTTPS scheme".to_string(),
            ));
        }

        let presentation_definition = client
            .get(presentation_definition_uri.as_str())
            .send()
            .await
            .context("send error")
            .map_err(VerificationProtocolError::Transport)?
            .error_for_status()
            .context("status error")
            .map_err(VerificationProtocolError::Transport)?
            .json()
            .context("parsing error")
            .map_err(VerificationProtocolError::Transport)?;

        authorization_request.presentation_definition = Some(presentation_definition);
    }

    Ok((authorization_request, verifier_did, verifier_certificate))
}

pub(crate) fn validate_interaction_data(
    interaction_data: &OpenID4VPHolderInteractionData,
) -> Result<(), VerificationProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }
    let response_type = interaction_data.response_type.as_ref().ok_or(
        VerificationProtocolError::InvalidRequest("response_type is None".to_string()),
    )?;
    assert_query_param(response_type, &["vp_token"], "response_type")?;

    let response_mode = interaction_data.response_mode.as_ref().ok_or(
        VerificationProtocolError::InvalidRequest("response_mode is None".to_string()),
    )?;
    assert_query_param(
        response_mode,
        &["direct_post", "direct_post.jwt"],
        "response_mode",
    )?;

    let client_metadata =
        interaction_data
            .client_metadata
            .as_ref()
            .ok_or(VerificationProtocolError::Failed(
                "client_metadata is None".to_string(),
            ))?;

    let mso_vp = client_metadata.vp_formats.get("mso_mdoc");
    let jwt_vp = client_metadata.vp_formats.get("jwt_vp_json");
    let ldp_vp = client_metadata.vp_formats.get("ldp_vp");
    let sd_jwt_vp = client_metadata
        .vp_formats
        .get("dc+sd-jwt")
        .or(client_metadata.vp_formats.get("vc+sd-jwt"));

    if jwt_vp.is_none() && sd_jwt_vp.is_none() && mso_vp.is_none() && ldp_vp.is_none() {
        Err(VerificationProtocolError::InvalidRequest(
            "unsupported client_metadata.vp_format must contain 'jwt_vp_json', 'vc+sd-jwt', 'dc+sd-jwt', 'mso_mdoc', or 'ldp_vp'".to_string(),
        ))?;
    }

    if let Some(jwt_vp) = jwt_vp {
        let OpenID4VpPresentationFormat::GenericAlgList(jwt_vp_json) = jwt_vp else {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats[\"jwt_vp_json\"] structure".to_string(),
            ))?;
        };

        if !jwt_vp_json.alg.contains(&"EdDSA".to_string()) {
            Err(VerificationProtocolError::InvalidRequest(
                "client_metadata.vp_formats[\"jwt_vp_json\"] must contain 'EdDSA' algorithm"
                    .to_string(),
            ))?;
        }
    };

    if let Some(ldp_vp) = ldp_vp {
        match ldp_vp {
            OpenID4VpPresentationFormat::LdpVcAlgs(ldp_vp_json) => {
                if !ldp_vp_json
                    .proof_type
                    .contains(&"DataIntegrityProof".to_string())
                {
                    Err(VerificationProtocolError::InvalidRequest(
                        "client_metadata.vp_formats[\"ldp_vp\"] must contain 'DataIntegrityProof' proof type"
                            .to_string(),
                    ))?;
                }
            }
            // TODO: Backwards compatibility,previous core versions incorrectly encoded the ldp_vp as a GenericAlgList
            OpenID4VpPresentationFormat::GenericAlgList(algs) => {
                if !algs.alg.contains(&"EdDSA".to_string()) {
                    Err(VerificationProtocolError::InvalidRequest(
                        "client_metadata.vp_formats[\"ldp_vp\"] must contain 'EdDSA' algorithm"
                            .to_string(),
                    ))?;
                }
            }
            _ => {
                return Err(VerificationProtocolError::InvalidRequest(
                    "invalid client_metadata.vp_formats[\"ldp_vp\"] structure".to_string(),
                ));
            }
        }
    }

    // TODO: Backwards compatibility, see ONE-5021
    if let Some(sd_jwt_vp) = sd_jwt_vp {
        let algorithms = match sd_jwt_vp {
            OpenID4VpPresentationFormat::GenericAlgList(algs) => &algs.alg,
            OpenID4VpPresentationFormat::SdJwtVcAlgs(algs) => &algs.sd_jwt_algorithms,
            _ => {
                return Err(VerificationProtocolError::InvalidRequest(
                    "invalid client_metadata.vp_formats[\"vc+sd-jwt\"] structure".to_string(),
                ));
            }
        };

        if !algorithms.contains(&"EdDSA".to_string()) && !algorithms.contains(&"ES256".to_string())
        {
            Err(VerificationProtocolError::InvalidRequest(
                "client_metadata.vp_formats[\"vc+sd-jwt\"] must contain 'EdDSA' or 'ES256' algorithms"
                    .to_string(),
            ))?;
        }
    };

    match mso_vp {
        Some(OpenID4VpPresentationFormat::GenericAlgList(mso_mdoc)) => {
            if !mso_mdoc.alg.contains(&"ES256".to_string())
                && !mso_mdoc.alg.contains(&"EdDSA".to_string())
            {
                Err(VerificationProtocolError::InvalidRequest(
                    "client_metadata.vp_formats[\"mso_mdoc\"] must contain 'ES256' or 'EdDSA' algorithms"
                        .to_string(),
                ))?;
            }
        }
        // As per the spec ONE-4912 - the mso_mdoc may contain no algorithms / be an empty object
        Some(OpenID4VpPresentationFormat::Other(serde_json::Value::Object(mso_mdoc))) => {
            if mso_mdoc.is_empty() {
                return Ok(());
            } else {
                return Err(VerificationProtocolError::InvalidRequest(
                    "client_metadata.vp_formats[\"mso_mdoc\"] must contain an 'alg' key or be an empty object".to_string(),
                ));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats[\"mso_mdoc\"] structure".to_string(),
            ));
        }
        None => {}
    };

    if interaction_data.response_uri.is_none() {
        return Err(VerificationProtocolError::InvalidRequest(
            "response_uri must be set".to_string(),
        ));
    }

    // If the Client Identifier scheme redirect_uri is used in conjunction with the Response Mode direct_post, and the response_uri parameter is present, the client_id value MUST be equal to the response_uri value.
    // <https://openid.net/specs/openid-4-verifiable-presentations-1_0-20.html#section-6.2-9>
    if interaction_data.client_id_scheme == ClientIdScheme::RedirectUri
        && Some(interaction_data.client_id.as_str())
            != interaction_data
                .response_uri
                .as_ref()
                .map(|uri| uri.as_str())
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "client_id must match response_uri".to_string(),
        ));
    }

    if interaction_data.nonce.is_none() {
        return Err(VerificationProtocolError::InvalidRequest(
            "nonce must be set".to_string(),
        ));
    }

    Ok(())
}

fn assert_query_param(
    value: &str,
    expected_values: &[&str],
    key: &str,
) -> Result<(), VerificationProtocolError> {
    if !expected_values.contains(&value) {
        return Err(VerificationProtocolError::InvalidRequest(format!(
            "{key} must be one of '[{}]'",
            expected_values.join(", ")
        )));
    }
    Ok(())
}
