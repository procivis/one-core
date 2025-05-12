use std::ops::Add;
use std::sync::Arc;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::common_mapper::get_encryption_key_jwk_from_proof;
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::jwt::model::{
    JWTHeader, JWTPayload, ProofOfPossessionJwk, ProofOfPossessionKey,
};
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::verification_protocol::error::VerificationProtocolError;
use crate::provider::verification_protocol::openid4vp::draft25::mappers::encode_client_id_with_scheme;
use crate::provider::verification_protocol::openid4vp::draft25::model::OpenID4VP25AuthorizationRequest;
use crate::provider::verification_protocol::openid4vp::mapper::create_open_id_for_vp_formats;
use crate::provider::verification_protocol::openid4vp::model::{
    ClientIdScheme, OpenID4VCVerifierAttestationPayload, OpenID4VPClientMetadata,
    OpenID4VPVerifierInteractionContent,
};
use crate::provider::verification_protocol::openid4vp::service::{
    create_open_id_for_vp_client_metadata, oidc_verifier_presentation_definition,
};
use crate::util::oidc::determine_response_mode;

pub(crate) async fn generate_authorization_request_client_id_scheme_redirect_uri(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
) -> Result<String, VerificationProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider,
        key_provider,
        ClientIdScheme::RedirectUri,
    )?;

    let unsigned_jwt = Jwt {
        header: JWTHeader {
            algorithm: "none".to_string(),
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at: None,
            invalid_before: None,
            issuer: None,
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: client_response,
        },
    };

    unsigned_jwt
        .tokenize(None)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) async fn generate_authorization_request_client_id_scheme_verifier_attestation(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, VerificationProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider.as_ref(),
        key_provider,
        ClientIdScheme::VerifierAttestation,
    )?;

    let JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let jwk = key_algorithm
        .reconstruct_key(&verifier_key.public_key, None, None)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
        .public_key_as_jwk()
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
    let proof_of_possession_key = Some(ProofOfPossessionKey {
        key_id: None,
        jwk: ProofOfPossessionJwk::Jwk { jwk: jwk.into() },
    });

    let verifier_did = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;
    let key_id = did_method_provider
        .get_verification_method_id_from_did_and_key(verifier_did, verifier_key)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    /*
     * TODO(ONE-3846): this needs to be issued and obtained from external authority,
     *     holder needs to know the authority and should check if it's signed by it
     */
    let response_uri = client_response
        .response_uri
        .as_ref()
        .map(|url| url.to_string())
        .unwrap_or_default();
    let custom = OpenID4VCVerifierAttestationPayload {
        redirect_uris: vec![response_uri],
    };

    let attestation_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm.to_owned(),
            key_id: Some(key_id),
            r#type: Some("verifier-attestation+jwt".to_string()),
            jwk: None,
            jwt: None,
            x5c: None,
        },
        payload: JWTPayload {
            expires_at,
            issuer: Some(verifier_did.did.to_string()),
            subject: Some(client_response.client_id.to_owned()),
            custom,
            proof_of_possession_key,
            ..Default::default()
        },
    }
    .tokenize(Some(auth_fn))
    .await
    .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let auth_fn = key_provider
        .get_signature_provider(verifier_key, None, key_algorithm_provider.clone())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: Some(attestation_jwt),
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: Some(client_response.client_id.to_owned()),
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: client_response,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) async fn generate_authorization_request_client_id_scheme_x509_san_dns(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
) -> Result<String, VerificationProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider.as_ref(),
        key_provider,
        ClientIdScheme::X509SanDns,
    )?;

    let JWTSigner {
        auth_fn,
        jose_algorithm,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let verifier_did = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;
    let x5c = if let Some(certificate) = verifier_did
        .did
        .as_str()
        .strip_prefix("did:mdl:certificate:")
    {
        let der = Base64UrlSafeNoPadding::decode_to_vec(certificate, None)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;
        Base64::encode_to_string(der)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?
    } else {
        return Err(VerificationProtocolError::Failed(
            "Invalid verifier did".to_string(),
        ));
    };

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: None,
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            x5c: Some(vec![x5c]),
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html#name-aud-of-a-request-object
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: client_response,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

pub(crate) async fn generate_authorization_request_client_id_scheme_did(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, VerificationProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider.as_ref(),
        key_provider,
        ClientIdScheme::Did,
    )?;

    let JWTSigner {
        auth_fn,
        jose_algorithm,
        verifier_key,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let verifier_did = proof
        .verifier_identifier
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_identifier is None".to_string(),
        ))?
        .did
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;

    let key_id = did_method_provider
        .get_verification_method_id_from_did_and_key(verifier_did, verifier_key)
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

    let request_jwt = Jwt {
        header: JWTHeader {
            algorithm: jose_algorithm,
            key_id: Some(key_id),
            r#type: Some("oauth-authz-req+jwt".to_string()),
            jwk: None,
            jwt: None,
            x5c: None,
        },
        payload: JWTPayload {
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: None,
            audience: Some(vec!["https://self-issued.me/v2".to_string()]),
            jwt_id: None,
            proof_of_possession_key: None,
            custom: client_response,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
        .await
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))
}

fn generate_authorization_request_params(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
    client_id_scheme: ClientIdScheme,
) -> Result<OpenID4VP25AuthorizationRequest, VerificationProtocolError> {
    let client_metadata = generate_client_metadata(proof, key_algorithm_provider, key_provider)?;

    let OpenID4VPVerifierInteractionContent {
        nonce,
        presentation_definition,
        client_id,
        response_uri: Some(response_uri),
        ..
    } = interaction_data
    else {
        return Err(VerificationProtocolError::Failed(
            "invalid interaction data".to_string(),
        ));
    };

    let presentation_definition =
        oidc_verifier_presentation_definition(proof, presentation_definition)
            .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let client_id = encode_client_id_with_scheme(client_id, client_id_scheme);
    Ok(OpenID4VP25AuthorizationRequest {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode(proof)?),
        client_id,
        client_metadata: Some(client_metadata),
        presentation_definition: Some(presentation_definition),
        response_uri: Some(
            Url::parse(&response_uri)
                .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        presentation_definition_uri: None,
        redirect_uri: None,
    })
}

fn generate_client_metadata(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    key_provider: &dyn KeyProvider,
) -> Result<OpenID4VPClientMetadata, VerificationProtocolError> {
    let vp_formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(proof, key_algorithm_provider, key_provider)
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    Ok(create_open_id_for_vp_client_metadata(
        jwk.key_id,
        jwk.jwk.into(),
        vp_formats,
    ))
}

struct JWTSigner<'a> {
    pub auth_fn: AuthenticationFn,
    pub verifier_key: &'a Key,
    pub key_algorithm: Arc<dyn KeyAlgorithm>,
    pub jose_algorithm: String,
}

fn get_jwt_signer<'a>(
    proof: &'a Proof,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
) -> Result<JWTSigner<'a>, VerificationProtocolError> {
    let verifier_key = proof
        .verifier_key
        .as_ref()
        .ok_or(VerificationProtocolError::Failed(
            "verifier_key is None".to_string(),
        ))?;

    let auth_fn = key_provider
        .get_signature_provider(verifier_key, None, key_algorithm_provider.to_owned())
        .map_err(|e| VerificationProtocolError::Failed(e.to_string()))?;

    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_name(&verifier_key.key_type)
        .ok_or(VerificationProtocolError::Failed(
            "algorithm not found".to_string(),
        ))?;

    let jose_algorithm =
        key_algorithm
            .issuance_jose_alg_id()
            .ok_or(VerificationProtocolError::Failed(
                "JOSE algorithm not found".to_string(),
            ))?;

    Ok(JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    })
}
