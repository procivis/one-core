use core::str;
use std::collections::BTreeSet;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use serde_json::json;
use shared_types::DidValue;
use standardized_types::openid4vp::PresentationFormat;
use url::Url;

use super::mappers::decode_client_id_with_scheme;
use super::model::{AuthorizationRequest, AuthorizationRequestQueryParams, Params};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::model::did::KeyRole;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CertificateValidator, ParsedCertificate,
};
use crate::proto::http_client::HttpClient;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::DecomposedJwt;
use crate::proto::key_verification::KeyVerification;
use crate::provider::credential_formatter::model::{
    CertificateDetails, IdentifierDetails, TokenVerifier,
};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::verification_protocol::openid4vp::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::final1_0::encode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCVerifierAttestationPayload, OpenID4VPClientMetadata,
    OpenID4VPHolderInteractionData,
};
use crate::provider::verification_protocol::openid4vp::validator::{
    validate_against_redirect_uris, validate_san_dns_matching_client_id,
    validate_x509_hash_matching_client_id,
};
use crate::validator::x509::is_dns_name_matching;

async fn parse_referenced_data_from_x509_san_dns_token(
    request_token: DecomposedJwt<AuthorizationRequest>,
    certificate_validator: &Arc<dyn CertificateValidator>,
) -> Result<(AuthorizationRequest, CertificateDetails), VerificationProtocolError> {
    let x5c = request_token
        .header
        .x5c
        .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

    let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

    let pem_chain = x5c_into_pem_chain(&x5c)
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

    let ParsedCertificate {
        public_key,
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(
            &pem_chain,
            CertificateValidationOptions::signature_and_revocation(None),
        )
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
        CertificateDetails {
            chain: pem_chain,
            fingerprint: attributes.fingerprint,
            expiry: attributes.not_after,
            subject_common_name,
        },
    ))
}

async fn parse_referenced_data_from_x509_hash_token(
    request_token: DecomposedJwt<AuthorizationRequest>,
    certificate_validator: &Arc<dyn CertificateValidator>,
) -> Result<(AuthorizationRequest, CertificateDetails), VerificationProtocolError> {
    let x5c = request_token
        .header
        .x5c
        .ok_or(VerificationProtocolError::Failed("x5c missing".to_string()))?;

    let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

    let pem_chain = x5c_into_pem_chain(&x5c)
        .map_err(|err| VerificationProtocolError::Failed(err.to_string()))?;

    let ParsedCertificate {
        public_key,
        attributes,
        subject_common_name,
        ..
    } = certificate_validator
        .parse_pem_chain(
            &pem_chain,
            CertificateValidationOptions::signature_and_revocation(None),
        )
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

    // client_id hash must match certificate fingerprint
    validate_x509_hash_matching_client_id(&attributes, &client_id)?;

    Ok((
        request_token.payload.custom,
        CertificateDetails {
            chain: pem_chain,
            fingerprint: attributes.fingerprint,
            expiry: attributes.not_after,
            subject_common_name,
        },
    ))
}

async fn parse_referenced_data_from_did_signed_token(
    request_token: DecomposedJwt<AuthorizationRequest>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
) -> Result<(AuthorizationRequest, DidValue), VerificationProtocolError> {
    let (client_id, _) = decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

    let Some(kid) = request_token.header.key_id.clone() else {
        return Err(VerificationProtocolError::Failed(
            "JOSE header missing kid".to_string(),
        ));
    };

    let verifier_did = client_id.parse().map_err(|_| {
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
    request_token: DecomposedJwt<AuthorizationRequest>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
) -> Result<(AuthorizationRequest, Option<String>), VerificationProtocolError> {
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
        .jwk;

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

    let client_id_without_prefix =
        attestation_jwt
            .payload
            .subject
            .ok_or(VerificationProtocolError::Failed(
                "missing `sub` in attestation JWT token".to_string(),
            ))?;

    Ok((
        AuthorizationRequest {
            client_id: encode_client_id_with_scheme(
                client_id_without_prefix,
                ClientIdScheme::VerifierAttestation,
            ),
            ..request_token.payload.custom
        },
        attestation_jwt.payload.issuer,
    ))
}

async fn retrieve_authorization_params_by_reference(
    query_params: AuthorizationRequestQueryParams,
    url: Url,
    client: &Arc<dyn HttpClient>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    params: &Params,
) -> Result<(AuthorizationRequest, Option<IdentifierDetails>), VerificationProtocolError> {
    let token = client
        .get(url.as_str())
        .header("Accept", "application/oauth-authz-req+jwt")
        .send()
        .await
        .context("Error calling request_uri")
        .and_then(|r| r.error_for_status().context("Response status error"))
        .and_then(|r| String::from_utf8(r.body).context("Invalid response"))
        .map_err(VerificationProtocolError::Transport)?;

    let request_token: DecomposedJwt<AuthorizationRequest> = Jwt::decompose_token(&token)
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
        decode_client_id_with_scheme(&request_token.payload.custom.client_id)?;

    if !params
        .holder
        .supported_client_id_schemes
        .contains(&client_id_scheme)
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "Unsupported client_id_scheme".into(),
        ));
    }

    let (referenced_params, verifier_details): (AuthorizationRequest, Option<IdentifierDetails>) =
        match client_id_scheme {
            ClientIdScheme::VerifierAttestation => {
                let (request, did) = parse_referenced_data_from_verifier_attestation_token(
                    request_token,
                    key_algorithm_provider,
                    did_method_provider,
                    certificate_validator,
                )
                .await?;
                (
                    request,
                    did.as_deref()
                        .map(DidValue::from_str)
                        .transpose()
                        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
                        .map(IdentifierDetails::Did),
                )
            }
            ClientIdScheme::RedirectUri => (request_token.payload.custom, None),
            ClientIdScheme::X509SanDns => {
                let (params, certificate) = parse_referenced_data_from_x509_san_dns_token(
                    request_token,
                    certificate_validator,
                )
                .await?;
                (params, Some(IdentifierDetails::Certificate(certificate)))
            }
            ClientIdScheme::X509Hash => {
                let (params, certificate) = parse_referenced_data_from_x509_hash_token(
                    request_token,
                    certificate_validator,
                )
                .await?;
                (params, Some(IdentifierDetails::Certificate(certificate)))
            }
            ClientIdScheme::Did => {
                let (request, did) = parse_referenced_data_from_did_signed_token(
                    request_token,
                    key_algorithm_provider,
                    did_method_provider,
                )
                .await?;
                (request, Some(IdentifierDetails::Did(did)))
            }
        };

    // client_id from the query params must match client_id inisde the token
    if referenced_params.client_id != query_params.client_id {
        return Err(VerificationProtocolError::InvalidRequest(
            "client_id mismatch with the request token".to_string(),
        ));
    }

    Ok((referenced_params, verifier_details))
}

pub(crate) async fn interaction_data_from_openid4vp_query(
    query: &str,
    client: &Arc<dyn HttpClient>,
    allow_insecure_http_transport: bool,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &Arc<dyn DidMethodProvider>,
    certificate_validator: &Arc<dyn CertificateValidator>,
    params: &Params,
) -> Result<(AuthorizationRequest, Option<IdentifierDetails>), VerificationProtocolError> {
    let query_params: AuthorizationRequestQueryParams = serde_qs::from_str(query)
        .map_err(|e| VerificationProtocolError::InvalidRequest(e.to_string()))?;

    let (authorization_request, verifier_details) =
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
                Ok((authorization_request, None))
            }
            (None, None) => {
                return Err(VerificationProtocolError::InvalidRequest(
                    "request or request_uri is required".to_string(),
                ));
            }
        }?;
    Ok((authorization_request, verifier_details))
}

pub(crate) fn validate_interaction_data(
    interaction_data: &OpenID4VPHolderInteractionData,
) -> Result<(), VerificationProtocolError> {
    if interaction_data.redirect_uri.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "redirect_uri must be None".to_string(),
        ));
    }

    if interaction_data.presentation_definition.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "presentation_definition must be None".to_string(),
        ));
    }

    if interaction_data.presentation_definition_uri.is_some() {
        return Err(VerificationProtocolError::InvalidRequest(
            "presentation_definition_uri must be None".to_string(),
        ));
    }

    let Some(dcql_query) = &interaction_data.dcql_query else {
        return Err(VerificationProtocolError::InvalidRequest(
            "dcql_query must be set".to_string(),
        ));
    };
    if let Some(credential_sets) = &dcql_query.credential_sets {
        for query_id in credential_sets
            .iter()
            .flat_map(|s| s.options.iter().flatten())
        {
            if !dcql_query.credentials.iter().any(|c| c.id == *query_id) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "invalid DCQL query: credential_set is referring to a non-existing credential query `{query_id}`"
                )));
            }
        }
    }

    let response_type = interaction_data.response_type.as_ref().ok_or(
        VerificationProtocolError::InvalidRequest("response_type is None".to_string()),
    )?;
    assert_query_param(response_type, &["vp_token"], "response_type")?;

    interaction_data
        .response_mode
        .ok_or(VerificationProtocolError::InvalidRequest(
            "response_mode is None".to_string(),
        ))?;

    let Some(OpenID4VPClientMetadata::Final1_0(client_metadata)) =
        interaction_data.client_metadata.as_ref()
    else {
        return Err(VerificationProtocolError::Failed(
            "client_metadata is None".to_string(),
        ));
    };

    let mso_mdoc = client_metadata.vp_formats_supported.get("mso_mdoc");
    let jwt_vc_json = client_metadata.vp_formats_supported.get("jwt_vc_json");
    let ldp_vc = client_metadata.vp_formats_supported.get("ldp_vc");
    let sd_jwt_vc = client_metadata.vp_formats_supported.get("dc+sd-jwt");

    if jwt_vc_json.is_none() && sd_jwt_vc.is_none() && mso_mdoc.is_none() && ldp_vc.is_none() {
        Err(VerificationProtocolError::InvalidRequest(
            "unsupported client_metadata.vp_formats_supported must contain 'jwt_vc_json', 'vc+sd-jwt', 'dc+sd-jwt', 'mso_mdoc', or 'ldp_vc'".to_string(),
        ))?;
    }

    let cose_supported = [-7, -8, -9, -19];
    let jose_supported = ["ES256".to_string(), "EdDSA".to_string()];

    /// find at least one common entry
    fn is_supported<T: Clone + Ord>(remotely_supported: &[T], locally_supported: &[T]) -> bool {
        if remotely_supported.is_empty() {
            return true; // no remotely specified means no known restrictions
        }

        let locally_supported = BTreeSet::from_iter(locally_supported);
        !locally_supported.is_disjoint(&BTreeSet::from_iter(remotely_supported))
    }

    match jwt_vc_json {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::W3CJwtAlgs(jwt_vc_json)) => {
            if !is_supported(&jwt_vc_json.alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'jwt_vc_json' ({:?}) does not contain a supported algorithm",
                    jwt_vc_json.alg_values
                )));
            }
        }
        Some(_) => {
            Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'jwt_vc_json'".to_string(),
            ))?;
        }
    };

    match ldp_vc {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::W3CLdpAlgs(ldp_vc)) => {
            if !is_supported(
                &ldp_vc.proof_type_values,
                &["DataIntegrityProof".to_string()],
            ) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'ldp_vc' ({:?}) must contain 'DataIntegrityProof' proof type",
                    ldp_vc.proof_type_values
                )));
            }

            if !is_supported(
                &ldp_vc.cryptosuite_values,
                &[
                    "bbs-2023".to_string(),
                    "ecdsa-rdfc-2019".to_string(),
                    "eddsa-rdfc-2022".to_string(),
                ],
            ) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'ldp_vc' ({:?}) does not contain a supported cryptosuite",
                    ldp_vc.cryptosuite_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'ldp_vc'".to_string(),
            ));
        }
    }

    match sd_jwt_vc {
        None | Some(PresentationFormat::Empty(_)) => {}
        Some(PresentationFormat::SdJwtVcAlgs(sd_jwt_vc)) => {
            if !is_supported(&sd_jwt_vc.sd_jwt_alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'dc+sd-jwt' ({:?}) does not contain a supported algorithm",
                    sd_jwt_vc.sd_jwt_alg_values
                )));
            }

            if !is_supported(&sd_jwt_vc.kb_jwt_alg_values, &jose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'dc+sd-jwt' ({:?}) does not contain a supported algorithm",
                    sd_jwt_vc.kb_jwt_alg_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported[\"dc+sd-jwt\"] structure".to_string(),
            ));
        }
    };

    // As per section B.3.2.3.2, ISO/IEC DTS 18013-7, an empty object is allowed
    match mso_mdoc {
        None
        | Some(PresentationFormat::Empty(_))
        // EUDI compatibility shim: allow null object and null values
        | Some(PresentationFormat::Other(serde_json::Value::Null)) => {}
         Some(PresentationFormat::Other(val)) if *val == json!({
                "issuerauth_alg_values": null,
                "deviceauth_alg_values": null
            }) => {}
        Some(PresentationFormat::MdocAlgs(mso_mdoc)) => {
            if !is_supported(&mso_mdoc.issuerauth_alg_values, &cose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'mso_mdoc' ({:?}) do not contain supported algorithms",
                    mso_mdoc.issuerauth_alg_values
                )));
            }

            if !is_supported(&mso_mdoc.deviceauth_alg_values, &cose_supported) {
                return Err(VerificationProtocolError::InvalidRequest(format!(
                    "client_metadata.vp_formats_supported entry for 'mso_mdoc' ({:?}) do not contain supported algorithms",
                    mso_mdoc.deviceauth_alg_values
                )));
            }
        }
        Some(_) => {
            return Err(VerificationProtocolError::InvalidRequest(
                "invalid client_metadata.vp_formats_supported entry for 'mso_mdoc'".to_string(),
            ));
        }
    };

    let Some(response_uri) = interaction_data.response_uri.as_ref() else {
        return Err(VerificationProtocolError::InvalidRequest(
            "response_uri must be set".to_string(),
        ));
    };
    if interaction_data.client_id_scheme == ClientIdScheme::RedirectUri
        && interaction_data.client_id.as_str() != response_uri.as_str()
    {
        return Err(VerificationProtocolError::InvalidRequest(
            "client_id must match response_uri for client_id_scheme=redirect_uri".to_string(),
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
