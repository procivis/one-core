use std::str::FromStr;

use one_crypto::utilities;
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use shared_types::NonceId;
use strum::Display;
use time::Duration;
use uuid::Uuid;

use super::error::OID4VCIFinal1_0ServiceError;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::proto::jwt::Jwt;
use crate::proto::jwt::hmac::HS256Signer;
use crate::proto::jwt::model::{DecomposedJwt, JWTPayload};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCNonceParams;
use crate::validator::{validate_expiration_time, validate_issuance_time};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwtPayload {
    context: Context,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Display)]
pub(super) enum Context {
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

pub(super) async fn generate_nonce(
    expiration: Duration,
    signing_key: SecretSlice<u8>,
    base_url: Option<String>,
    context: Context,
) -> Result<String, OID4VCIFinal1_0ServiceError> {
    let now = crate::clock::now_utc();

    let payload = JWTPayload::<JwtPayload> {
        jwt_id: Some(Uuid::new_v4().to_string()),
        issued_at: Some(now),
        expires_at: Some(now + expiration),
        issuer: base_url,
        invalid_before: Some(now),
        subject: None,
        audience: None,
        proof_of_possession_key: None,
        custom: JwtPayload { context },
    };
    let jwt = Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload);

    Ok(jwt
        .tokenize(Some(&HS256Signer::new(signing_key)))
        .await
        .error_while("creating nonce token")?)
}

pub(super) fn validate_nonce(
    params: &OpenID4VCNonceParams,
    base_url: Option<&String>,
    nonce: &str,
    context: Context,
) -> Result<NonceId, OID4VCIFinal1_0ServiceError> {
    let DecomposedJwt::<JwtPayload> {
        header,
        payload,
        signature,
        unverified_jwt,
    } = Jwt::decompose_token(nonce).error_while("parsing nonce token")?;

    if header.algorithm != "HS256" {
        return Err(
            FormatterError::CouldNotVerify("Invalid nonce alg header".to_string())
                .error_while("validating algorithm")
                .into(),
        );
    };

    let (Some(issued_at), Some(expires_at), Some(issuer)) =
        (payload.issued_at, payload.expires_at, payload.issuer)
    else {
        return Err(
            FormatterError::CouldNotVerify("Invalid payload".to_string())
                .error_while("validating payload")
                .into(),
        );
    };
    validate_issuance_time(&Some(issued_at), params.leeway_seconds)
        .error_while("checking validity")?;
    validate_expiration_time(&Some(expires_at), params.leeway_seconds)
        .error_while("checking validity")?;
    if Some(&issuer) != base_url {
        return Err(
            FormatterError::CouldNotVerify(format!("Invalid nonce issuer: {issuer}"))
                .error_while("validating issuer")
                .into(),
        );
    }
    if payload.custom.context != context {
        return Err(FormatterError::CouldNotVerify(format!(
            "Invalid nonce context: {}",
            payload.custom.context
        ))
        .error_while("validating context")
        .into());
    }

    let id = payload
        .jwt_id
        .ok_or(FormatterError::CouldNotVerify(
            "Missing nonce_id".to_string(),
        ))
        .error_while("validating nonce_id")?;
    let id = Uuid::from_str(&id)
        .map_err(|e| FormatterError::CouldNotVerify(format!("Invalid nonce_id: {e}")))
        .error_while("validating nonce_id")?;

    let expected_signature = utilities::create_hmac(
        params.signing_key.expose_secret(),
        unverified_jwt.as_bytes(),
    )
    .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))
    .error_while("validating signature")?;
    if expected_signature != signature {
        return Err(
            FormatterError::CouldNotVerify("Invalid nonce signature".to_string())
                .error_while("verifying signature")
                .into(),
        );
    }

    Ok(id.into())
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;
    use time::Duration;

    use super::*;
    use crate::error::{ErrorCode, ErrorCodeMixin};

    #[tokio::test]
    async fn test_generate_and_validate_openid4vci_nonce() {
        let base_url = "http://test.com";
        let params = params();
        let nonce = generate_nonce(
            params.expiration_seconds,
            params.signing_key.clone(),
            Some(base_url.to_string()),
            Context::OpenID4VCINonce,
        )
        .await
        .unwrap();

        validate_nonce(
            &params,
            Some(&base_url.to_string()),
            &nonce,
            Context::OpenID4VCINonce,
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
            Context::OAuthAttestationChallenge,
        )
        .await
        .unwrap();

        validate_nonce(
            &params,
            Some(&base_url.to_string()),
            &nonce,
            Context::OAuthAttestationChallenge,
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
            Context::OpenID4VCINonce,
        )
        .await
        .unwrap();

        let result = validate_nonce(
            &params,
            Some(&base_url.to_string()),
            &nonce,
            Context::OAuthAttestationChallenge,
        );
        assert_eq!(result.unwrap_err().error_code(), ErrorCode::BR_0057);
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
