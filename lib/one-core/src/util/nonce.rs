use std::str::FromStr;

use one_crypto::utilities;
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use shared_types::NonceId;
use strum::Display;
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::hmac::HS256Signer;
use crate::proto::jwt::model::{DecomposedJwt, JWTPayload};
use crate::validator::{validate_expiration_time, validate_issuance_time};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct NoncePayload {
    pub context: NonceContext,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Display)]
pub(crate) enum NonceContext {
    /// <https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-nonce-endpoint>
    #[serde(rename = "issuance-openidvci-final-1.0-nonce")]
    OpenID4VCINonce,
    /// <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth-11#name-challenges>
    #[serde(rename = "oauth-attestation-challenge")]
    OAuthAttestationChallenge,
    /// <https://www.rfc-editor.org/rfc/rfc9449.html#name-authorization-server-provid>
    #[serde(rename = "dpop-nonce")]
    DPoPNonce,
}

#[derive(Debug, Error)]
pub enum NonceError {
    #[error("Invalid nonce: `{0}`")]
    Invalid(String),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for NonceError {
    fn error_code(&self) -> ErrorCode {
        match self {
            NonceError::Nested(err) => err.error_code(),
            _ => ErrorCode::BR_0518,
        }
    }
}

pub(crate) async fn generate_nonce(
    expiration: Duration,
    signing_key: SecretSlice<u8>,
    base_url: Option<String>,
    context: NonceContext,
) -> Result<String, NonceError> {
    let now = crate::clock::now_utc();

    let payload = JWTPayload::<NoncePayload> {
        jwt_id: Some(Uuid::new_v4().to_string()),
        issued_at: Some(now),
        expires_at: Some(now + expiration),
        issuer: base_url,
        invalid_before: Some(now),
        subject: None,
        audience: None,
        proof_of_possession_key: None,
        custom: NoncePayload { context },
    };
    let jwt = Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload);

    Ok(jwt
        .tokenize(Some(&HS256Signer::new(signing_key)))
        .await
        .error_while("creating nonce token")?)
}

#[derive(Debug, Clone)]
pub(crate) struct NonceInfo {
    pub id: NonceId,
    pub expires_at: OffsetDateTime,
}

pub(crate) fn validate_nonce(
    leeway: Duration,
    signing_key: SecretSlice<u8>,
    base_url: Option<&String>,
    nonce: &str,
    context: NonceContext,
) -> Result<NonceInfo, NonceError> {
    let DecomposedJwt::<NoncePayload> {
        header,
        payload,
        signature,
        unverified_jwt,
    } = Jwt::decompose_token(nonce).error_while("parsing nonce token")?;

    if header.algorithm != "HS256" {
        return Err(NonceError::Invalid(format!(
            "Invalid nonce algorithm: {}",
            header.algorithm
        )));
    };

    let (Some(issued_at), Some(expires_at), Some(issuer)) =
        (payload.issued_at, payload.expires_at, payload.issuer)
    else {
        return Err(NonceError::Invalid("Invalid payload".to_string()));
    };
    validate_issuance_time(&Some(issued_at), leeway).error_while("checking iat")?;
    validate_expiration_time(&Some(expires_at), leeway).error_while("checking expiration")?;
    if Some(&issuer) != base_url {
        return Err(NonceError::Invalid(format!(
            "Invalid nonce issuer: {issuer}"
        )));
    }
    if payload.custom.context != context {
        return Err(NonceError::Invalid(format!(
            "Invalid nonce context: {}",
            payload.custom.context
        )));
    }

    let id = payload
        .jwt_id
        .ok_or(NonceError::Invalid("Missing nonce_id".to_string()))?;
    let id = Uuid::from_str(&id)
        .map_err(|e| NonceError::Invalid(format!("Invalid nonce_id: {e}")))?
        .into();

    let expected_signature =
        utilities::create_hmac(signing_key.expose_secret(), unverified_jwt.as_bytes())
            .map_err(|e| NonceError::Invalid(format!("Failed to create signature: {e}")))?;
    if expected_signature != signature {
        return Err(NonceError::Invalid("Invalid nonce signature".to_string()));
    }

    Ok(NonceInfo { id, expires_at })
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use time::Duration;

    use super::*;
    use crate::error::{ErrorCode, ErrorCodeMixin};
    use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCNonceParams;

    #[tokio::test]
    async fn test_generate_and_validate_openid4vci_nonce() {
        let base_url = "http://test.com";
        let params = params();
        let nonce = generate_nonce(
            params.expiration_seconds,
            params.signing_key.clone(),
            Some(base_url.to_string()),
            NonceContext::OpenID4VCINonce,
        )
        .await
        .unwrap();

        validate_nonce(
            params.leeway_seconds,
            params.signing_key,
            Some(&base_url.to_string()),
            &nonce,
            NonceContext::OpenID4VCINonce,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_generate_and_validate_oauth_challenge() {
        let base_url = "http://test.com";
        let params = params();
        let nonce = generate_nonce(
            params.expiration_seconds,
            params.signing_key.clone(),
            Some(base_url.to_string()),
            NonceContext::OAuthAttestationChallenge,
        )
        .await
        .unwrap();

        validate_nonce(
            params.leeway_seconds,
            params.signing_key,
            Some(&base_url.to_string()),
            &nonce,
            NonceContext::OAuthAttestationChallenge,
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_generate_and_validate_context_mismatch() {
        let base_url = "http://test.com";
        let params = params();
        let nonce = generate_nonce(
            params.expiration_seconds,
            params.signing_key.clone(),
            Some(base_url.to_string()),
            NonceContext::OpenID4VCINonce,
        )
        .await
        .unwrap();

        let result = validate_nonce(
            params.leeway_seconds,
            params.signing_key,
            Some(&base_url.to_string()),
            &nonce,
            NonceContext::OAuthAttestationChallenge,
        );
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0518);
    }

    fn params() -> OpenID4VCNonceParams {
        OpenID4VCNonceParams {
            signing_key: hex::decode(
                "c213ff6fb1a57a0c7353443527a7cd5775c3c58b8f32476dee8200fb5767904d",
            )
            .unwrap()
            .into(),
            expiration_seconds: Duration::seconds(300),
            leeway_seconds: Default::default(),
        }
    }
}
