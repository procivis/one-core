//! Implementations for JWT credential format.

use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Debug;

use anyhow::Context;
use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder};
use mapper::{bin_to_b64url_string, string_to_b64url_string};
use one_crypto::SignerError;
use serde::Serialize;
use serde::de::DeserializeOwned;
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;

use self::model::{DecomposedJwt, JWTHeader};
use crate::config::core_config::KeyAlgorithmType;
use crate::proto::jwt::model::{DecomposedToken, Payload, SerdeSkippable};
use crate::provider::credential_formatter::error::FormatterError;
use crate::provider::credential_formatter::model::{
    CredentialClaim, PublicKeySource, SignatureProvider, TokenVerifier, VerificationFn,
};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[cfg(test)]
mod test;

pub mod mapper;
pub mod model;

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
    ) -> Result<(), SignerError> {
        self.as_ref()
            .verify(public_key_source, algorithm, token, signature)
            .await
    }

    fn key_algorithm_provider(&self) -> &dyn KeyAlgorithmProvider {
        self.as_ref().key_algorithm_provider()
    }
}

pub type Jwt<CustomPayload> = JwtImpl<Option<String>, CustomPayload>;

#[derive(Debug)]
pub struct JwtImpl<Subject: SerdeSkippable, CustomPayload> {
    pub header: JWTHeader,
    pub payload: Payload<Subject, CustomPayload>,
}

#[derive(Debug, Clone)]
pub enum JwtPublicKeyInfo {
    Jwk(PublicJwk),
    X5c(Vec<String>),
}

impl<Subject: SerdeSkippable, CustomPayload> JwtImpl<Subject, CustomPayload> {
    pub fn new(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        public_key_info: Option<JwtPublicKeyInfo>,
        payload: Payload<Subject, CustomPayload>,
    ) -> JwtImpl<Subject, CustomPayload> {
        Self::new_with_attestation(r#type, algorithm, key_id, public_key_info, None, payload)
    }

    pub fn new_with_attestation(
        r#type: String,
        algorithm: String,
        key_id: Option<String>,
        public_key_info: Option<JwtPublicKeyInfo>,
        attestation_jwt: Option<String>,
        payload: Payload<Subject, CustomPayload>,
    ) -> JwtImpl<Subject, CustomPayload> {
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
            key_attestation: attestation_jwt,
            x5c,
        };

        JwtImpl { header, payload }
    }
}

impl<Subject: Serialize + SerdeSkippable, CustomPayload: WithMetadata + Serialize>
    JwtImpl<Subject, CustomPayload>
{
    pub fn get_metadata_claims(&self) -> Result<HashMap<String, CredentialClaim>, FormatterError> {
        let value = serde_json::to_value(&self.payload)
            .map_err(|e| FormatterError::JsonMapping(e.to_string()))?;

        let Some(obj) = value.as_object() else {
            return Err(FormatterError::Failed(
                "Expected root to be an object".to_string(),
            ));
        };

        let mut result = HashMap::new();
        for key in ["iss", "aud", "sub", "jti", "exp", "nbf", "iat"] {
            let Some(claim) = obj.get(key) else { continue };
            let mut claim = CredentialClaim::try_from(claim.clone())?;
            claim.set_metadata(true);
            result.insert(key.to_string(), claim);
        }
        result.extend(self.payload.custom.get_metadata_claims()?);
        Ok(result)
    }
}

impl<Subject, CustomPayload> JwtImpl<Subject, CustomPayload>
where
    Subject: DeserializeOwned + Debug + SerdeSkippable,
    CustomPayload: DeserializeOwned + Debug,
{
    pub async fn build_from_token(
        token: &str,
        verification: Option<&VerificationFn>,
        issuer_did: Option<DidValue>,
    ) -> Result<JwtImpl<Subject, CustomPayload>, FormatterError> {
        let DecomposedToken {
            header,
            mut payload,
            signature,
            unverified_jwt,
        } = JwtImpl::decompose_token(token)?;

        if let (Some(issuer), Some(issuer_did)) = (&payload.issuer, &issuer_did)
            && issuer != issuer_did.as_str()
        {
            return Err(FormatterError::CouldNotVerify(format!(
                "Token issuer `{issuer}` does not match credential issuer `{issuer_did}`",
            )));
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

            let issuer_did = payload
                .issuer
                .as_ref()
                .map(|did| did.parse::<DidValue>().context("did parsing error"))
                .transpose()
                .map_err(|e| FormatterError::Failed(e.to_string()))?
                .or(issuer_did);

            let public_key_source = match (issuer_did, &header.x5c, &header.jwk) {
                (Some(issuer_did), None, None) => PublicKeySource::Did {
                    did: Cow::Owned(issuer_did),
                    key_id: header.key_id.as_deref(),
                },
                (None, Some(x5c), None) => PublicKeySource::X5c { x5c },
                (None, None, Some(jwk)) => PublicKeySource::Jwk {
                    jwk: Cow::Owned(jwk.to_owned()),
                },
                (None, None, None) => {
                    return Err(FormatterError::CouldNotVerify(
                        "Missing public key information for JWT".to_string(),
                    ));
                }
                (did, x5c, jwk) => {
                    return Err(FormatterError::CouldNotVerify(format!(
                        "Mixed specification of public key info: did:{did:?}, x5c:{x5c:?}, jwk:{jwk:?}",
                    )));
                }
            };

            verification
                .verify(
                    public_key_source,
                    algorithm.algorithm_type(),
                    unverified_jwt.as_bytes(),
                    &signature,
                )
                .await
                .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))?;
        }

        let jwt = JwtImpl { header, payload };

        Ok(jwt)
    }

    pub fn decompose_token(
        token: &str,
    ) -> Result<DecomposedToken<Subject, CustomPayload>, FormatterError> {
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

        let payload: Payload<Subject, CustomPayload> = serde_json::from_slice(&payload_decoded)
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

impl<Subject: Serialize + SerdeSkippable, CustomPayload: Serialize>
    JwtImpl<Subject, CustomPayload>
{
    // todo: this probably needs to be a "sign" function on an UnsignedJwt type
    pub async fn tokenize(
        &self,
        auth_fn: Option<&dyn SignatureProvider>,
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

impl<T> DecomposedJwt<T> {
    pub async fn verify_signature(
        &self,
        public_key_source: PublicKeySource<'_>,
        token_verifier: &dyn TokenVerifier,
    ) -> Result<(), FormatterError> {
        let (_, algorithm) = token_verifier
            .key_algorithm_provider()
            .key_algorithm_from_jose_alg(&self.header.algorithm)
            .ok_or(FormatterError::CouldNotVerify(format!(
                "Missing key algorithm for {}",
                self.header.algorithm
            )))?;

        token_verifier
            .verify(
                public_key_source,
                algorithm.algorithm_type(),
                self.unverified_jwt.as_bytes(),
                &self.signature,
            )
            .await
            .map_err(|e| FormatterError::CouldNotVerify(e.to_string()))
    }
}
