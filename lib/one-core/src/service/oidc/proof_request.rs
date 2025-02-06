use std::ops::Add;
use std::sync::Arc;

use ct_codecs::{Base64, Base64UrlSafeNoPadding, Decoder, Encoder};
use time::{Duration, OffsetDateTime};
use url::Url;

use crate::common_mapper::get_encryption_key_jwk_from_proof;
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::model::proof::Proof;
use crate::provider::credential_formatter::jwt::model::{
    JWTHeader, JWTPayload, ProofOfPossessionKey,
};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::credential_formatter::model::AuthenticationFn;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::error::ExchangeProtocolError;
use crate::provider::exchange_protocol::openid4vc::mapper::create_open_id_for_vp_formats;
use crate::provider::exchange_protocol::openid4vc::model::{
    ClientIdSchemaType, OpenID4VPAuthorizationRequestParams, OpenID4VPClientMetadata,
    OpenID4VPVerifierInteractionContent,
};
use crate::provider::exchange_protocol::openid4vc::service::{
    create_open_id_for_vp_client_metadata, oidc_verifier_presentation_definition,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::provider::key_algorithm::KeyAlgorithm;
use crate::provider::key_storage::provider::KeyProvider;
use crate::util::oidc::determine_response_mode;

pub(crate) async fn generate_authorization_request_client_id_scheme_redirect_uri(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<String, ExchangeProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider,
        ClientIdSchemaType::RedirectUri,
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
            jwt_id: None,
            vc_type: None,
            custom: client_response,
            proof_of_possession_key: None,
        },
    };

    unsigned_jwt
        .tokenize(None)
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

pub(crate) async fn generate_authorization_request_client_id_scheme_verifier_attestation(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, ExchangeProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider.as_ref(),
        ClientIdSchemaType::VerifierAttestation,
    )?;

    let JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let jwk = key_algorithm
        .reconstruct_key(&verifier_key.public_key, None, None)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
        .public_key_as_jwk()
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
    let proof_of_possession_key = Some(ProofOfPossessionKey {
        key_id: None,
        jwk: jwk.into(),
    });

    let verifier_did = proof
        .verifier_did
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;
    let key_id = did_method_provider
        .get_verification_method_id_from_did_and_key(verifier_did, verifier_key)
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let expires_at = Some(OffsetDateTime::now_utc().add(Duration::hours(1)));

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
            issued_at: None,
            expires_at,
            invalid_before: None,
            issuer: Some(verifier_did.did.to_string()),
            subject: Some(client_response.client_id.to_owned()),
            jwt_id: None,
            custom: (),
            proof_of_possession_key,
            vc_type: None,
        },
    }
    .tokenize(Some(auth_fn))
    .await
    .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let auth_fn = key_provider
        .get_signature_provider(verifier_key, None, key_algorithm_provider.clone())
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

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
            jwt_id: None,
            custom: client_response,
            proof_of_possession_key: None,
            vc_type: None,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

pub(crate) async fn generate_authorization_request_client_id_scheme_x509_san_dns(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    key_provider: &dyn KeyProvider,
) -> Result<String, ExchangeProtocolError> {
    let client_response = generate_authorization_request_params(
        proof,
        interaction_data,
        interaction_id,
        key_algorithm_provider.as_ref(),
        ClientIdSchemaType::X509SanDns,
    )?;

    let JWTSigner {
        auth_fn,
        jose_algorithm,
        ..
    } = get_jwt_signer(proof, key_algorithm_provider, key_provider)?;

    let verifier_did = proof
        .verifier_did
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "verifier_did is None".to_string(),
        ))?;
    let x5c = if let Some(certificate) = verifier_did
        .did
        .as_str()
        .strip_prefix("did:mdl:certificate:")
    {
        let der = Base64UrlSafeNoPadding::decode_to_vec(certificate, None)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;
        Base64::encode_to_string(der).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?
    } else {
        return Err(ExchangeProtocolError::Failed(
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
            subject: None,
            jwt_id: None,
            custom: client_response,
            proof_of_possession_key: None,
            vc_type: None,
        },
    };

    request_jwt
        .tokenize(Some(auth_fn))
        .await
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))
}

fn generate_authorization_request_params(
    proof: &Proof,
    interaction_data: OpenID4VPVerifierInteractionContent,
    interaction_id: &InteractionId,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    client_id_scheme: ClientIdSchemaType,
) -> Result<OpenID4VPAuthorizationRequestParams, ExchangeProtocolError> {
    let client_metadata =
        generate_client_metadata(proof, key_algorithm_provider, client_id_scheme)?;

    let OpenID4VPVerifierInteractionContent {
        nonce,
        presentation_definition,
        client_id,
        response_uri: Some(response_uri),
        ..
    } = interaction_data
    else {
        return Err(ExchangeProtocolError::Failed(
            "invalid interaction data".to_string(),
        ));
    };

    let presentation_definition =
        oidc_verifier_presentation_definition(proof, presentation_definition)
            .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    Ok(OpenID4VPAuthorizationRequestParams {
        response_type: Some("vp_token".to_string()),
        response_mode: Some(determine_response_mode(proof)?),
        client_id,
        client_id_scheme: Some(client_id_scheme),
        client_metadata: Some(client_metadata),
        presentation_definition: Some(presentation_definition),
        response_uri: Some(
            Url::parse(&response_uri).map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?,
        ),
        nonce: Some(nonce),
        state: Some(interaction_id.to_string()),
        client_metadata_uri: None,
        presentation_definition_uri: None,
        redirect_uri: None,
    })
}

fn generate_client_metadata(
    proof: &Proof,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
    client_id_scheme: ClientIdSchemaType,
) -> Result<OpenID4VPClientMetadata, ExchangeProtocolError> {
    let vp_formats = create_open_id_for_vp_formats();
    let jwk = get_encryption_key_jwk_from_proof(proof, key_algorithm_provider)
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    Ok(create_open_id_for_vp_client_metadata(
        jwk.key_id,
        jwk.jwk.into(),
        vp_formats,
        client_id_scheme,
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
) -> Result<JWTSigner<'a>, ExchangeProtocolError> {
    let verifier_key = proof
        .verifier_key
        .as_ref()
        .ok_or(ExchangeProtocolError::Failed(
            "verifier_key is None".to_string(),
        ))?;

    let auth_fn = key_provider
        .get_signature_provider(verifier_key, None, key_algorithm_provider.to_owned())
        .map_err(|e| ExchangeProtocolError::Failed(e.to_string()))?;

    let key_algorithm = key_algorithm_provider
        .key_algorithm_from_name(&verifier_key.key_type)
        .ok_or(ExchangeProtocolError::Failed(
            "algorithm not found".to_string(),
        ))?;

    let jose_algorithm =
        key_algorithm
            .issuance_jose_alg_id()
            .ok_or(ExchangeProtocolError::Failed(
                "JOSE algorithm not found".to_string(),
            ))?;

    Ok(JWTSigner {
        auth_fn,
        verifier_key,
        key_algorithm,
        jose_algorithm,
    })
}
