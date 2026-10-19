use std::ops::Add;
use std::sync::Arc;

use async_trait::async_trait;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_crypto::hasher::sha256::SHA256;
use one_crypto::{Hasher, HasherError};
use secrecy::SecretSlice;
use shared_types::{DpopNonce, InteractionId};
use standardized_types::oauth2::dpop::{DPOP_JWT_TYPE, DPoPClaims};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use url::Url;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::proto::jwt::{Jwt, TokenError};
use crate::provider::key_algorithm::error::KeyAlgorithmError;
use crate::provider::key_algorithm::key::KeyHandleError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::error::DataLayerError;
use crate::repository::interaction_repository::InteractionRepository;
use crate::util::nonce::{NonceContext, NonceError, NonceInfo, generate_nonce, validate_nonce};
use crate::validator::{TimestampValidationError, validate_issuance_time};

#[cfg(test)]
mod test;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait DpopHandler: Send + Sync {
    async fn generate_nonce(&self, params: DpopParams) -> Result<DpopNonce, DpopHandlerError>;
    async fn validate_proof<'a>(
        &'a self,
        interaction_id: InteractionId,
        proof: &'a str,
        access_token: Option<&'a str>,
        expectations: ExpectedProofValues<'a>,
        params: DpopParams,
    ) -> Result<ProofValidationOutput, DpopHandlerError>;
}

#[derive(Debug, Clone)]
pub struct DpopParams {
    pub nonce_validity: Duration,
    pub nonce_refresh_threshold: Duration,
    pub leeway: Duration,
    pub signing_key: SecretSlice<u8>,
    pub proof_signing_algorithms: Vec<KeyAlgorithmType>,
    pub base_url: Option<String>,
    pub swiyu_mode: bool,
}

pub struct ExpectedProofValues<'a> {
    pub method: &'static str,
    pub url: Url,
    pub jkt: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct ProofValidationOutput {
    pub nonce: Option<DpopNonce>,
    pub jkt: String,
}

#[derive(Debug, Error)]
pub enum DpopHandlerError {
    #[error("DPoP proof `typ` is not `dpop+jwt`")]
    InvalidType,
    #[error("DPoP proof has no `jwk` header")]
    MissingJwk,
    #[error("DPoP proof has no `iat` claim")]
    MissingIssuedAt,
    #[error("DPoP proof has no `jti` claim")]
    MissingJwtId,
    #[error("DPoP proof `htm` does not match the request method")]
    MethodMismatch,
    #[error("DPoP proof `htu` does not match the request URL")]
    UrlMismatch,
    #[error("DPoP proof `iat` is outside of the accepted time window: `{0}`")]
    IssuedAtOutOfWindow(#[from] TimestampValidationError),
    #[error("DPoP proof `ath` does not match the access token")]
    AccessTokenMismatch,
    #[error("DPoP proof `alg` is not supported")]
    UnsupportedAlgorithm,
    #[error("Missing nonce in DPoP proof")]
    MissingNonce,
    #[error("DPoP proof key is not the key the token is bound to")]
    KeyMismatch,
    #[error("DPoP proof has already been used")]
    AlreadyUsed,

    #[error("Invalid DPoP nonce: `{0}`")]
    InvalidNonce(#[from] NonceError),
    #[error("DPoP proof is not a valid JWT: `{0}`")]
    InvalidJwt(#[from] TokenError),
    #[error("DPoP proof `jwk` is not a valid public key: `{0}`")]
    InvalidJwk(#[from] KeyAlgorithmError),
    #[error("DPoP proof signature is invalid: `{0}`")]
    InvalidSignature(#[from] KeyHandleError),
    #[error("Hasher error: `{0}`")]
    HashingError(#[from] HasherError),
    #[error("Mapping error: `{0}`")]
    MappingError(String),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl From<ct_codecs::Error> for DpopHandlerError {
    fn from(value: ct_codecs::Error) -> Self {
        Self::MappingError(format!("Base64 error: {value}"))
    }
}

impl From<serde_json::Error> for DpopHandlerError {
    fn from(value: serde_json::Error) -> Self {
        Self::MappingError(format!("JSON error: {value}"))
    }
}

impl From<uuid::Error> for DpopHandlerError {
    fn from(value: uuid::Error) -> Self {
        Self::MappingError(format!("UUID: {value}"))
    }
}

impl ErrorCodeMixin for DpopHandlerError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::MissingNonce | Self::InvalidNonce(_) => ErrorCode::BR_0520,
            Self::Nested(err) => err.error_code(),
            _ => ErrorCode::BR_0517,
        }
    }
}

pub struct DpopHandlerImpl {
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    interaction_repository: Arc<dyn InteractionRepository>,
}

impl DpopHandlerImpl {
    pub fn new(
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        interaction_repository: Arc<dyn InteractionRepository>,
    ) -> Self {
        Self {
            key_algorithm_provider,
            interaction_repository,
        }
    }

    async fn validate_nonce(
        &self,
        interaction_id: InteractionId,
        jti: &str,
        nonce: &str,
        params: DpopParams,
    ) -> Result<OffsetDateTime, DpopHandlerError> {
        let NonceInfo { id, expires_at } = validate_nonce(
            params.leeway,
            params.signing_key,
            params.base_url.as_ref(),
            nonce,
            NonceContext::DPoPNonce,
        )?;
        let nonce_hash = SHA256.hash(format!("{}-{}", jti, id).as_bytes())?;
        let nonce_id = Uuid::from_slice(nonce_hash.get(..16).ok_or(
            DpopHandlerError::MappingError("Invalid hash length".to_string()),
        )?)?
        .into();
        let result = self
            .interaction_repository
            .mark_nonces_as_used(&interaction_id, vec![nonce_id])
            .await;
        match result {
            Ok(()) => {}
            Err(DataLayerError::AlreadyExists(_)) => {
                return Err(DpopHandlerError::AlreadyUsed);
            }
            err => err.error_while("marking DPoP proof as used")?,
        }
        Ok(expires_at)
    }
}

#[async_trait]
impl DpopHandler for DpopHandlerImpl {
    async fn generate_nonce(&self, params: DpopParams) -> Result<DpopNonce, DpopHandlerError> {
        let nonce = generate_nonce(
            params.nonce_validity,
            params.signing_key,
            params.base_url,
            NonceContext::DPoPNonce,
        )
        .await
        .error_while("generating nonce")?;
        Ok(DpopNonce::from(nonce))
    }

    async fn validate_proof<'a>(
        &'a self,
        interaction_id: InteractionId,
        proof: &'a str,
        access_token: Option<&'a str>,
        expectations: ExpectedProofValues<'a>,
        params: DpopParams,
    ) -> Result<ProofValidationOutput, DpopHandlerError> {
        let proof =
            Jwt::<DPoPClaims>::decompose_token(proof).map_err(DpopHandlerError::InvalidJwt)?;
        if !proof
            .header
            .r#type
            .as_deref()
            .is_some_and(|r#type| r#type.eq_ignore_ascii_case(DPOP_JWT_TYPE))
        {
            return Err(DpopHandlerError::InvalidType);
        }
        let jwk = proof
            .header
            .jwk
            .as_ref()
            .ok_or(DpopHandlerError::MissingJwk)?;

        let claims = &proof.payload.custom;
        if claims.htm != expectations.method {
            return Err(DpopHandlerError::MethodMismatch);
        }
        if claims.htu != expectations.url {
            return Err(DpopHandlerError::UrlMismatch);
        }
        let issued_at = proof
            .payload
            .issued_at
            .ok_or(DpopHandlerError::MissingIssuedAt)?;
        // proof freshness is enforced by the expiry of the mandatory server-issued nonce
        validate_issuance_time(&Some(issued_at), params.leeway)?;
        let Some(jti) = &proof.payload.jwt_id else {
            return Err(DpopHandlerError::MissingJwtId);
        };
        if let Some(access_token) = access_token {
            let ath = SHA256.hash_base64_url(access_token.as_bytes())?;
            let ath_matches = claims.ath.as_deref() == Some(ath.as_str())
                // Swiyu workaround: https://github.com/swiyu-admin-ch/eidch-android-wallet/blob/c29a6f3af51f14c47cf23ab88933522ffa1fbef0/openid4vc/src/main/java/ch/admin/foitt/openid4vc/domain/usecase/implementation/CreateDPoPProofJwtImpl.kt#L90
                || (params.swiyu_mode && claims.ath.as_deref() == Some(format!("{ath}=").as_str()));
            if !ath_matches {
                return Err(DpopHandlerError::AccessTokenMismatch);
            }
        }
        let (alg_type, key_algorithm) = self
            .key_algorithm_provider
            .key_algorithm_from_jose_alg(&proof.header.algorithm)
            .ok_or(DpopHandlerError::UnsupportedAlgorithm)?;
        if !params.proof_signing_algorithms.contains(&alg_type) {
            return Err(DpopHandlerError::UnsupportedAlgorithm);
        }

        key_algorithm
            .parse_jwk(jwk)
            .map_err(DpopHandlerError::InvalidJwk)?
            .verify(proof.unverified_jwt.as_bytes(), &proof.signature)
            .map_err(DpopHandlerError::InvalidSignature)?;

        let thumbprint = jwk.thumbprint()?;
        let jkt = Base64UrlSafeNoPadding::encode_to_string(thumbprint)?;
        if let Some(expected_jkt) = expectations.jkt
            && jkt != expected_jkt
        {
            return Err(DpopHandlerError::KeyMismatch);
        }

        let Some(nonce) = &claims.nonce else {
            return Err(DpopHandlerError::MissingNonce);
        };
        let nonce_expiry = self
            .validate_nonce(interaction_id, jti, nonce, params.clone())
            .await?;
        let nonce = if nonce_expiry < crate::clock::now_utc().add(params.nonce_refresh_threshold) {
            Some(self.generate_nonce(params).await?)
        } else {
            None
        };
        Ok(ProofValidationOutput { nonce, jkt })
    }
}
