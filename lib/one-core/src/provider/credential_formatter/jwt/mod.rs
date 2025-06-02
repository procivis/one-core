//! Implementations for JWT credential format.

use std::fmt::Debug;

use anyhow::Context;
use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_crypto::SignerError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::DidValue;

use self::model::{DecomposedToken, JWTHeader, JWTPayload};
use super::model::{PublicKeySource, VerificationFn};
use crate::config::core_config::KeyAlgorithmType;
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, TokenVerifier};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::key::dto::PublicKeyJwkDTO;

#[cfg(test)]
mod test;

pub mod mapper;
pub mod model;

pub type AnyPayload = serde_json::Map<String, serde_json::Value>;

#[async_trait]
impl TokenVerifier for Box<dyn TokenVerifier> {
    async fn verify<'a>(
        &self,
        public_key_source: PublicKeySource<'a>,
        algorithm: KeyAlgorithmType,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        self.as_ref()
            .verify(public_key_source, algorithm, token, signature)
            .await
    }

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider {
        self.as_ref().key_algorithm_provider()
    }
}

#[derive(Debug)]
pub struct Jwt<Payload> {
    pub header: JWTHeader,
    pub payload: JWTPayload<Payload>,
}

pub enum JwtPublicKeyInfo {
    Jwk(PublicKeyJwkDTO),
    X5c(Vec<String>),
}

impl<Payload> Jwt<Payload> {
    pub fn new(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        public_key_info: Option<JwtPublicKeyInfo>,
        payload: JWTPayload<Payload>,
    ) -> Jwt<Payload> {
        let (jwk, x5c) = match public_key_info {
            None => (None, None),
            Some(JwtPublicKeyInfo::Jwk(jwk)) => (Some(jwk), None),
            Some(JwtPublicKeyInfo::X5c(vec)) => (None, Some(vec)),
        };

        let header = JWTHeader {
            r#type: Some(r#type),
            algorithm,
            key_id,
            jwk,
            jwt: None,
            x5c,
        };

        Jwt { header, payload }
    }
}

impl<Payload: DeserializeOwned + Debug> Jwt<Payload> {
    pub async fn build_from_token(
        token: &str,
        verification: Option<&VerificationFn>,
        issuer_did: Option<DidValue>,
    ) -> Result<Jwt<Payload>, FormatterError> {
        let DecomposedToken {
            header,
            mut payload,
            signature,
            unverified_jwt,
        } = Jwt::decompose_token(token)?;

        if let (Some(issuer), Some(issuer_did)) = (&payload.issuer, &issuer_did) {
            if issuer != issuer_did.as_str() {
                return Err(FormatterError::CouldNotVerify(format!(
                    "Token issuer `{issuer}` does not match credential issuer `{issuer_did}`",
                )));
            }
        }

        payload.issuer = payload.issuer.map(|issuer| {
            if issuer.starts_with("did:") {
                issuer
            } else {
                format!(
                    "did:sd_jwt_vc_issuer_metadata:{}",
                    urlencoding::encode(&issuer)
                )
            }
        });

        if let Some(verification) = verification {
            let (_, algorithm) = verification
                .key_algorithm_provider()
                .key_algorithm_from_jose_alg(&header.algorithm)
                .ok_or(FormatterError::CouldNotVerify(format!(
                    "Missing key algorithm for {}",
                    header.algorithm
                )))?;

            let did = payload
                .issuer
                .as_ref()
                .map(|did| did.parse().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?
                .or(issuer_did)
                .ok_or(FormatterError::Failed("missing did value".to_string()))?;
            let params = PublicKeySource::Did {
                did: &did,
                key_id: header.key_id.as_deref(),
            };
            verification
                .verify(
                    params,
                    algorithm.algorithm_type(),
                    unverified_jwt.as_bytes(),
                    &signature,
                )
                .await
                .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        }

        let jwt = Jwt { header, payload };

        Ok(jwt)
    }

    pub fn decompose_token(token: &str) -> Result<DecomposedToken<Payload>, FormatterError> {
        let token = token.trim_matches(|c: char| c == '.' || c.is_whitespace());
        let mut jwt_parts = token.splitn(3, '.');

        let (Some(header), Some(payload), maybe_signature) =
            (jwt_parts.next(), jwt_parts.next(), jwt_parts.next())
        else {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing token part".to_owned(),
            ));
        };

        let unverified_jwt = [header, payload].join(".");

        let header_decoded = Base64UrlSafeNoPadding::decode_to_vec(header, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let header: JWTHeader = serde_json::from_slice(&header_decoded)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let payload_decoded = Base64UrlSafeNoPadding::decode_to_vec(payload, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let payload: JWTPayload<Payload> = serde_json::from_slice(&payload_decoded)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let signature = maybe_signature
            .map(|signature| {
                Base64UrlSafeNoPadding::decode_to_vec(signature, None)
                    .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))
            })
            .transpose()?
            .unwrap_or_default();

        Ok(DecomposedToken {
            header,
            payload,
            signature,
            unverified_jwt,
        })
    }
}

impl<Payload: Serialize> Jwt<Payload> {
    // todo: this probably needs to be a "sign" function on an UnsignedJwt type
    pub async fn tokenize(
        &self,
        auth_fn: Option<AuthenticationFn>,
    ) -> Result<String, FormatterError> {
        let jwt_header_json = serde_json::to_string(&self.header)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let payload_json = serde_json::to_string(&self.payload)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let mut token = format!(
            "{}.{}",
            string_to_b64url_string(&jwt_header_json)?,
            string_to_b64url_string(&payload_json)?,
        );

        if let Some(auth_fn) = auth_fn {
            let signature = auth_fn
                .sign(token.as_bytes())
                .await
                .map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

            if !signature.is_empty() {
                let signature_encoded = bin_to_b64url_string(&signature)?;

                token.push('.');
                token.push_str(&signature_encoded);
            }
        }

        Ok(token)
    }
}
