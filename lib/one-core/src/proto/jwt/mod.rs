//! Implementations for JWT credential format.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mapper::{bin_to_b64url_string, string_to_b64url_string};
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;

use self::model::{DecomposedJwt, JWTHeader};
use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::jwt::model::JWTPayload;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, PublicKeySource, SignatureProvider, TokenVerifier, VerificationFn,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg(test)]
mod test;

pub(crate) mod hmac;
pub mod mapper;
pub mod model;
pub(crate) mod rsa;

pub type AnyPayload = serde_json::Map<String, serde_json::Value>;

pub trait WithMetadata {
    fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, FormatterError>;
}

#[async_trait]
impl TokenVerifier for Box<dyn TokenVerifier> {
    async fn verify<'a>(
        &self,
        public_key_source: PublicKeySource<'a>,
        algorithm: KeyAlgorithmType,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), TokenError> {
        self.as_ref()
            .verify(public_key_source, algorithm, token, signature)
            .await
    }

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider {
        self.as_ref().key_algorithm_provider()
    }
}

#[derive(Debug)]
pub struct Jwt<CustomPayload> {
    pub header: JWTHeader,
    pub payload: JWTPayload<CustomPayload>,
}

#[derive(Debug, Clone)]
pub enum JwtPublicKeyInfo {
    Jwk(PublicJwk),
    X5c(Vec<String>),
    X5cAndU {
        chain: Vec<String>,
        url: String,
        fingerprint: String,
    },
}

impl<CustomPayload> Jwt<CustomPayload> {
    pub fn new(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        public_key_info: Option<JwtPublicKeyInfo>,
        payload: JWTPayload<CustomPayload>,
    ) -> Jwt<CustomPayload> {
        Self::new_with_attestation(r#type, algorithm, key_id, public_key_info, None, payload)
    }

    pub fn new_with_attestation(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        public_key_info: Option<JwtPublicKeyInfo>,
        attestation_jwt: Option<String>,
        payload: JWTPayload<CustomPayload>,
    ) -> Jwt<CustomPayload> {
        let (jwk, x5c, x5u, x5t_s256) = match public_key_info {
            None => (None, None, None, None),
            Some(JwtPublicKeyInfo::Jwk(jwk)) => (Some(jwk), None, None, None),
            Some(JwtPublicKeyInfo::X5c(x5c)) => (None, Some(x5c), None, None),
            Some(JwtPublicKeyInfo::X5cAndU {
                chain,
                fingerprint,
                url,
            }) => (None, Some(chain), Some(url), Some(fingerprint)),
        };

        let header = JWTHeader {
            r#type: Some(r#type),
            algorithm,
            key_id,
            jwk,
            jwt: None,
            key_attestation: attestation_jwt,
            x5c,
            x5u,
            x5t_s256,
        };

        Jwt { header, payload }
    }
}

impl<CustomPayload: WithMetadata + Serialize> Jwt<CustomPayload> {
    pub fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, TokenError> {
        let value = serde_json::to_value(&self.payload)?;

        let Some(obj) = value.as_object() else {
            return Err(TokenError::ValidationFailed(
                "Expected root to be an object".to_string(),
            ));
        };

        let mut result = HashMap::new();
        for key in ["iss", "aud", "sub", "jti", "exp", "nbf", "iat"] {
            let Some(claim) = obj.get(key) else { continue };
            let mut claim = CredentialClaim::try_from(claim.clone())
                .error_while("extracting metadata claim")?;
            claim.set_metadata(true);
            result.insert(key.to_string(), claim);
        }
        result.extend(
            self.payload
                .custom
                .get_metadata_claims()
                .error_while("getting metadata claims")?,
        );
        Ok(result)
    }
}

impl<CustomPayload> Jwt<CustomPayload>
where
    CustomPayload: DeserializeOwned + Debug,
{
    pub async fn build_from_token(
        token: &str,
        verification: Option<&VerificationFn>,
        issuer_did: Option<DidValue>,
    ) -> Result<Jwt<CustomPayload>, TokenError> {
        let token = Jwt::decompose_token(token)?;

        if let (Some(issuer), Some(issuer_did)) = (&token.payload.issuer, &issuer_did)
            && issuer != issuer_did.as_str()
        {
            return Err(TokenError::ValidationFailed(format!(
                "Token issuer `{issuer}` does not match credential issuer `{issuer_did}`",
            )));
        }

        if let Some(token_verifier) = verification {
            let public_key_source =
                token.public_key_source(issuer_did.map(|did| PublicKeySource::Did {
                    did: Cow::Owned(did),
                    key_id: token.header.key_id.as_deref(),
                }))?;
            token
                .verify_signature(public_key_source, token_verifier)
                .await?;
        }

        Ok(Jwt {
            header: token.header,
            payload: token.payload,
        })
    }

    pub fn decompose_token(token: &str) -> Result<DecomposedJwt<CustomPayload>, TokenError> {
        let token = token.trim_matches(|c: char| c == '.' || c.is_whitespace());
        let mut jwt_parts = token.splitn(3, '.');

        let (Some(header), Some(payload), maybe_signature) =
            (jwt_parts.next(), jwt_parts.next(), jwt_parts.next())
        else {
            return Err(TokenError::ValidationFailed(
                "Missing token part".to_string(),
            ));
        };

        let unverified_jwt = [header, payload].join(".");

        let header_decoded = Base64UrlSafeNoPadding::decode_to_vec(header, None)?;
        let header: JWTHeader = serde_json::from_slice(&header_decoded)?;

        let payload_decoded = Base64UrlSafeNoPadding::decode_to_vec(payload, None)?;
        let payload: JWTPayload<CustomPayload> = serde_json::from_slice(&payload_decoded)?;

        let signature = maybe_signature
            .map(|signature| Base64UrlSafeNoPadding::decode_to_vec(signature, None))
            .transpose()?
            .unwrap_or_default();

        Ok(DecomposedJwt {
            header,
            payload,
            signature,
            unverified_jwt,
        })
    }
}

impl<CustomPayload: Serialize> Jwt<CustomPayload> {
    // todo: this probably needs to be a "sign" function on an UnsignedJwt type
    pub async fn tokenize(
        &self,
        auth_fn: Option<&dyn SignatureProvider>,
    ) -> Result<String, TokenError> {
        let jwt_header_json = serde_json::to_string(&self.header)?;
        let payload_json = serde_json::to_string(&self.payload)?;
        let mut token = format!(
            "{}.{}",
            string_to_b64url_string(&jwt_header_json)?,
            string_to_b64url_string(&payload_json)?,
        );

        if let Some(auth_fn) = auth_fn {
            let signature = auth_fn
                .sign(token.as_bytes())
                .await
                .error_while("signing")?;

            if !signature.is_empty() {
                let signature_encoded = bin_to_b64url_string(&signature)?;

                token.push('.');
                token.push_str(&signature_encoded);
            }
        }

        Ok(token)
    }
}

impl<T> DecomposedJwt<T> {
    pub fn public_key_source<'a>(
        &'a self,
        externally_defined: Option<PublicKeySource<'a>>,
    ) -> Result<PublicKeySource<'a>, TokenError> {
        let did = self
            .payload
            .issuer
            .as_ref()
            .and_then(|did| did.parse::<DidValue>().ok());

        let extracted = match (did, &self.header.x5c, &self.header.jwk) {
            (Some(did), None, None) => PublicKeySource::Did {
                did: Cow::Owned(did),
                key_id: self.header.key_id.as_deref(),
            },
            (None, Some(x5c), None) => PublicKeySource::X5c { x5c },
            (None, None, Some(jwk)) => PublicKeySource::Jwk {
                jwk: Cow::Owned(jwk.to_owned()),
            },
            (None, None, None) => {
                return externally_defined.ok_or(TokenError::ValidationFailed(
                    "Missing public key information for JWT".to_string(),
                ));
            }
            (did, x5c, jwk) => {
                return Err(TokenError::ValidationFailed(format!(
                    "Mixed specification of public key info: did:{did:?}, x5c:{x5c:?}, jwk:{jwk:?}",
                )));
            }
        };

        if let Some(external) = externally_defined
            && extracted != external
        {
            return Err(TokenError::ValidationFailed(format!(
                "Token issuer `{extracted:?}` does not match externally defined `{external:?}`",
            )));
        }

        Ok(extracted)
    }

    pub async fn verify_signature(
        &self,
        public_key_source: PublicKeySource<'_>,
        token_verifier: &dyn TokenVerifier,
    ) -> Result<(), TokenError> {
        let (_, algorithm) = token_verifier
            .key_algorithm_provider()
            .key_algorithm_from_jose_alg(&self.header.algorithm)
            .ok_or(TokenError::MissingJOSEAlgorithm(
                self.header.algorithm.to_owned(),
            ))?;

        token_verifier
            .verify(
                public_key_source,
                algorithm.algorithm_type(),
                self.unverified_jwt.as_bytes(),
                &self.signature,
            )
            .await?;

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TokenError {
    #[error("Unknown JOSE algorithm `{0}`")]
    MissingJOSEAlgorithm(String),
    #[error("Validation failed: `{0}`")]
    ValidationFailed(String),

    #[error("Serialization error: `{0}`")]
    SerializationError(#[from] serde_json::Error),
    #[error("Encoding error: `{0}`")]
    EncodingError(#[from] ct_codecs::Error),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for TokenError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingJOSEAlgorithm(_)
            | Self::ValidationFailed(_)
            | Self::SerializationError(_)
            | Self::EncodingError(_) => ErrorCode::BR_0355,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
