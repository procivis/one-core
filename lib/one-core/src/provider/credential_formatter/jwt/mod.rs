use std::fmt::Debug;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use serde::{de::DeserializeOwned, Serialize};

use crate::{
    crypto::signer::SignerError,
    provider::credential_formatter::jwt::mapper::{bin_to_b64url_string, string_to_b64url_string},
};

use self::{
    mapper::json_from_decoded,
    model::{DecomposedToken, JWTHeader, JWTPayload},
};

use super::error::FormatterError;

#[cfg(test)]
mod test;

pub mod mapper;
pub mod model;

pub type AuthenticationFn = Box<dyn FnOnce(&str) -> Result<Vec<u8>, SignerError>>;

#[async_trait]
pub trait TokenVerifier {
    async fn verify<'a>(
        &self,
        issuer_did_value: &'a str,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError>;
}

#[derive(Default)]
pub struct SkipVerification;

#[async_trait]
impl TokenVerifier for SkipVerification {
    async fn verify<'a>(
        &self,
        _issuer_did_value: &'a str,
        _algorithm: &'a str,
        _token: &'a str,
        _signature: &'a [u8],
    ) -> Result<(), SignerError> {
        Ok(())
    }
}

#[async_trait]
impl TokenVerifier for Box<dyn TokenVerifier + Send + Sync> {
    async fn verify<'a>(
        &self,
        issuer_did_value: &'a str,
        algorithm: &'a str,
        token: &'a str,
        signature: &'a [u8],
    ) -> Result<(), SignerError> {
        TokenVerifier::verify(self, issuer_did_value, algorithm, token, signature).await
    }
}

#[derive(Debug)]
pub struct Jwt<Payload: Serialize + DeserializeOwned + Debug + Send + Sync> {
    pub(crate) header: JWTHeader,
    pub(crate) payload: JWTPayload<Payload>,
}

impl<Payload: Serialize + DeserializeOwned + Debug + Send + Sync> Jwt<Payload> {
    pub fn new(
        signature_type: String,
        algorithm: String,
        key_id: Option<String>,
        payload: JWTPayload<Payload>,
    ) -> Jwt<Payload> {
        let header = JWTHeader {
            signature_type: Some(signature_type),
            algorithm,
            key_id,
        };

        Jwt { header, payload }
    }

    pub async fn build_from_token(
        token: &str,
        verification: impl TokenVerifier,
    ) -> Result<Jwt<Payload>, FormatterError> {
        let DecomposedToken {
            header,
            header_json,
            payload,
            payload_json,
            signature,
        } = Jwt::decompose_token(token)?;

        let jwt = format!(
            "{}.{}",
            string_to_b64url_string(&header_json)?,
            string_to_b64url_string(&payload_json)?,
        );

        let issuer = payload
            .issuer
            .as_ref()
            .ok_or(FormatterError::MissingIssuer)?;

        verification
            .verify(issuer, &header.algorithm, &jwt, &signature)
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;

        let jwt = Jwt { header, payload };

        Ok(jwt)
    }

    pub fn tokenize(&self, auth_fn: AuthenticationFn) -> Result<String, FormatterError> {
        let jwt_header_json = serde_json::to_string(&self.header)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let payload_json = serde_json::to_string(&self.payload)
            .map_err(|e| FormatterError::CouldNotFormat(e.to_string()))?;
        let mut token = format!(
            "{}.{}",
            string_to_b64url_string(&jwt_header_json)?,
            string_to_b64url_string(&payload_json)?,
        );

        let signature = auth_fn(&token).map_err(|e| FormatterError::CouldNotSign(e.to_string()))?;

        if !signature.is_empty() {
            let signature_encoded = bin_to_b64url_string(&signature)?;

            token.push('.');
            token.push_str(&signature_encoded);
        }

        Ok(token)
    }

    fn decompose_token(token: &str) -> Result<DecomposedToken<Payload>, FormatterError> {
        let token = token.trim_matches(|c: char| c == '.' || c.is_whitespace());
        let mut jwt_parts = token.splitn(3, '.');

        let (Some(header), Some(payload), Some(signature)) =
            (jwt_parts.next(), jwt_parts.next(), jwt_parts.next())
        else {
            return Err(FormatterError::CouldNotExtractCredentials(
                "Missing token part".to_owned(),
            ));
        };

        let header_decoded = Base64UrlSafeNoPadding::decode_to_vec(header, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let header: JWTHeader = serde_json::from_slice(&header_decoded)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let payload_decoded = Base64UrlSafeNoPadding::decode_to_vec(payload, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let payload: JWTPayload<Payload> = serde_json::from_slice(&payload_decoded)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        let signature = Base64UrlSafeNoPadding::decode_to_vec(signature, None)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?;

        Ok(DecomposedToken {
            header,
            header_json: json_from_decoded(header_decoded)?,
            payload,
            payload_json: json_from_decoded(payload_decoded)?,
            signature,
        })
    }
}
