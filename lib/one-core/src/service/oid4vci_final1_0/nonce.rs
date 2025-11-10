use std::str::FromStr;

use one_crypto::{SignerError, utilities};
use secrecy::{ExposeSecret, SecretSlice};
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::proto::jwt::Jwt;
use crate::proto::jwt::model::{DecomposedToken, JWTPayload};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::SignatureProvider;
use crate::provider::issuance_protocol::openid4vci_final1_0::model::OpenID4VCNonceParams;
use crate::service::error::ServiceError;
use crate::validator::{validate_expiration_time, validate_issuance_time};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct NonceJwtPayload {
    context: String,
}

const CONTEXT: &str = "issuance-openidvci-final-1.0-nonce";

impl Default for NonceJwtPayload {
    fn default() -> Self {
        Self {
            context: CONTEXT.to_string(),
        }
    }
}

pub(super) async fn generate_nonce(
    params: OpenID4VCNonceParams,
    base_url: Option<String>,
) -> Result<String, ServiceError> {
    let expiration = params.expiration.unwrap_or(300);
    let now = OffsetDateTime::now_utc();

    let payload = JWTPayload::<NonceJwtPayload> {
        jwt_id: Some(Uuid::new_v4().to_string()),
        issued_at: Some(now),
        expires_at: Some(now + Duration::seconds(expiration as _)),
        issuer: base_url,
        ..Default::default()
    };
    let jwt = Jwt::new("JWT".to_string(), "HS256".to_string(), None, None, payload);

    Ok(jwt
        .tokenize(Some(&HS256Signer {
            signing_key: params.signing_key,
        }))
        .await?)
}

pub(super) fn validate_nonce(
    params: OpenID4VCNonceParams,
    base_url: Option<String>,
    nonce: &str,
) -> Result<Uuid, ServiceError> {
    let DecomposedToken::<NonceJwtPayload> {
        header,
        payload,
        signature,
        unverified_jwt,
    } = Jwt::decompose_token(nonce)?;

    if header.algorithm != "HS256" {
        return Err(FormatterError::CouldNotVerify("Invalid nonce alg header".to_string()).into());
    };

    let (Some(issued_at), Some(expires_at), Some(issuer)) =
        (payload.issued_at, payload.expires_at, payload.issuer)
    else {
        return Err(FormatterError::CouldNotVerify("Invalid payload".to_string()).into());
    };
    validate_issuance_time(&Some(issued_at), params.leeway)?;
    validate_expiration_time(&Some(expires_at), params.leeway)?;
    if Some(&issuer) != base_url.as_ref() {
        return Err(
            FormatterError::CouldNotVerify(format!("Invalid nonce issuer: {issuer}")).into(),
        );
    }
    if payload.custom.context != CONTEXT {
        return Err(FormatterError::CouldNotVerify(format!(
            "Invalid nonce context: {}",
            payload.custom.context
        ))
        .into());
    }

    let id = payload.jwt_id.ok_or(FormatterError::CouldNotVerify(
        "Missing nonce_id".to_string(),
    ))?;
    let id = Uuid::from_str(&id)
        .map_err(|e| FormatterError::CouldNotVerify(format!("Invalid nonce_id: {e}")))?;

    let expected_signature = utilities::create_hmac(
        params.signing_key.expose_secret(),
        unverified_jwt.as_bytes(),
    )
    .ok_or(FormatterError::CouldNotVerify("HMAC failure".to_string()))?;
    if expected_signature != signature {
        return Err(FormatterError::CouldNotVerify("Invalid nonce signature".to_string()).into());
    }

    Ok(id)
}

struct HS256Signer {
    pub signing_key: SecretSlice<u8>,
}

#[async_trait::async_trait]
impl SignatureProvider for HS256Signer {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignerError> {
        utilities::create_hmac(self.signing_key.expose_secret(), message)
            .ok_or(SignerError::CouldNotSign("HMAC failure".to_string()))
    }

    fn get_key_id(&self) -> Option<String> {
        None
    }

    fn get_key_algorithm(&self) -> Result<KeyAlgorithmType, String> {
        Err("HS256".to_string())
    }

    fn jose_alg(&self) -> Option<String> {
        Some("HS256".to_string())
    }

    fn get_public_key(&self) -> Vec<u8> {
        Default::default()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_generate_and_validate_nonce() {
        let base_url = "http://test.com";
        let nonce = generate_nonce(params(), Some(base_url.to_string()))
            .await
            .unwrap();

        validate_nonce(params(), Some(base_url.to_string()), &nonce).unwrap();
    }

    fn params() -> OpenID4VCNonceParams {
        OpenID4VCNonceParams {
            signing_key: hex::decode(
                "c213ff6fb1a57a0c7353443527a7cd5775c3c58b8f32476dee8200fb5767904d",
            )
            .unwrap()
            .into(),
            expiration: Some(300),
            leeway: 0,
        }
    }
}
