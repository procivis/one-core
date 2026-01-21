use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use super::certificate_validator::CertificateValidator;
use super::jwt::Jwt;
use super::jwt::model::{JWTHeader, JWTPayload};
use super::key_verification::KeyVerification;
use crate::KeyProvider;
use crate::model::did::KeyRole;
use crate::model::identifier::{Identifier, IdentifierType};
use crate::provider::credential_formatter::model::VerificationFn;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::{MissingProviderError, ServiceError, ValidationError};
use crate::util::key_selection::KeyFilter;
use crate::validator::validate_expiration_time;

/// JWT authorization token for use of authenticated holder/verifier access (LVVC fetching, remote trust-entity)
pub(crate) async fn prepare_bearer_token(
    identifier: &Identifier,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
) -> Result<String, ServiceError> {
    let (key, key_id, issuer) = match identifier.r#type {
        IdentifierType::Key => {
            let key = identifier.key.to_owned().ok_or(ServiceError::MappingError(
                "Missing identifier key".to_string(),
            ))?;

            (key, None, None)
        }
        IdentifierType::Did => {
            let did = identifier.did.as_ref().ok_or(ServiceError::MappingError(
                "Missing identifier did".to_string(),
            ))?;

            let authentication_key = did
                .find_first_matching_key(&KeyFilter::role_filter(KeyRole::Authentication))?
                .ok_or(ValidationError::KeyNotFound)?;

            let key_id = did.verification_method_id(authentication_key);

            (
                authentication_key.key.to_owned(),
                Some(key_id),
                Some(did.did.to_string()),
            )
        }
        IdentifierType::Certificate | IdentifierType::CertificateAuthority => {
            return Err(ServiceError::MappingError(format!(
                "Invalid holder identifier type {}",
                identifier.r#type
            )));
        }
    };

    let key_algorithm = key
        .key_algorithm_type()
        .and_then(|alg| key_algorithm_provider.key_algorithm_from_type(alg))
        .ok_or_else(|| {
            ServiceError::MissingProvider(MissingProviderError::KeyAlgorithmProvider(
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(key.key_type.to_owned()),
            ))
        })?;

    let jwk = if issuer.is_none() {
        Some(
            key_algorithm
                .reconstruct_key(&key.public_key, None, None)?
                .public_key_as_jwk()?,
        )
    } else {
        None
    };

    let payload = JWTPayload {
        issuer,
        custom: BearerTokenPayload {
            timestamp: OffsetDateTime::now_utc(),
        },
        ..Default::default()
    };

    let algorithm = key_algorithm
        .issuance_jose_alg_id()
        .ok_or(ServiceError::MappingError("Missing JOSE alg".to_string()))?;

    let signer = key_provider.get_signature_provider(&key, None, key_algorithm_provider.clone())?;
    let bearer_token = Jwt::<BearerTokenPayload> {
        header: JWTHeader {
            algorithm,
            key_id,
            r#type: None,
            jwk,
            jwt: None,
            key_attestation: None,
            x5c: None,
        },
        payload,
    }
    .tokenize(Some(&*signer))
    .await?;

    Ok(bearer_token)
}

/// Validation of the bearer token signature and timestamp freshness
pub(crate) async fn validate_bearer_token(
    bearer_token: &str,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
    leeway: u64,
) -> Result<Jwt<BearerTokenPayload>, ServiceError> {
    let token_signature_verification: VerificationFn = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::Authentication,
        certificate_validator,
    });

    let jwt: Jwt<BearerTokenPayload> =
        Jwt::build_from_token(bearer_token, Some(&(token_signature_verification)), None).await?;

    // checking timestamp to prevent replay attack
    validate_expiration_time(&Some(jwt.payload.custom.timestamp), leeway)
        .map_err(|_| ServiceError::ValidationError("Bearer token expired".to_owned()))?;

    Ok(jwt)
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct BearerTokenPayload {
    #[serde(with = "time::serde::timestamp")]
    pub timestamp: OffsetDateTime,
}

// provide default so that JWTPayload can have Default too
impl Default for BearerTokenPayload {
    fn default() -> Self {
        Self {
            // use invalid (always expired unix epoch) as default,
            // to not accidentally extract a valid timestamp while decoding an incoming JWT token
            timestamp: OffsetDateTime::UNIX_EPOCH,
        }
    }
}
