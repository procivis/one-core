//! Implementations for JWT credential format.

use std::fmt::Debug;

use anyhow::Context;
use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_crypto::SignerError;
use serde::de::DeserializeOwned;
use serde::Serialize;
use shared_types::DidValue;

use self::model::{DecomposedToken, JWTHeader, JWTPayload};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{AuthenticationFn, TokenVerifier};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::key::dto::PublicKeyJwkDTO;

#[cfg(test)]
mod test;

pub mod mapper;
pub mod model;

#[async_trait]
impl TokenVerifier for Box<dyn TokenVerifier> {
    async fn verify<'a>(
        &self,
        issuer_did_value: Option<DidValue>,
        issuer_key_id: Option<&'a str>,
        algorithm: &'a str,
        token: &'a [u8],
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        self.as_ref()
            .verify(issuer_did_value, issuer_key_id, algorithm, token, signature)
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

impl<Payload> Jwt<Payload> {
    pub fn new(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        jwk: Option<PublicKeyJwkDTO>,
        payload: JWTPayload<Payload>,
    ) -> Jwt<Payload> {
        let header = JWTHeader {
            r#type: Some(r#type),
            algorithm,
            key_id,
            jwk,
            jwt: None,
        };

        Jwt { header, payload }
    }
}

impl<Payload: DeserializeOwned> Jwt<Payload> {
    pub async fn build_from_token(
        token: &str,
        verification: Option<Box<dyn TokenVerifier>>,
    ) -> Result<Jwt<Payload>, FormatterError> {
        let DecomposedToken {
            header,
            payload,
            signature,
            unverified_jwt,
        } = Jwt::decompose_token(token)?;

        if let Some(verification) = verification {
            let (_, algorithm) = verification
                .key_algorithm_provider()
                .get_key_algorithm_from_jose_alg(&header.algorithm)
                .ok_or(FormatterError::CouldNotVerify(format!(
                    "Missing key algorithm for {}",
                    header.algorithm
                )))?;

            verification
                .verify(
                    payload
                        .issuer
                        .as_ref()
                        .map(|did| did.parse().context("did parsing error"))
                        .transpose()
                        .map_err(|e| FormatterError::Failed(e.to_string()))?,
                    header.key_id.as_deref(),
                    &algorithm,
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
