use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::KeyProvider;
use crate::common_validator::validate_expiration_time;
use crate::model::did::{Did, KeyFilter, KeyRole};
use crate::provider::credential_formatter::model::TokenVerifier;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::certificate::validator::CertificateValidator;
use crate::service::error::{MissingProviderError, ServiceError, ValidationError};
use crate::util::jwt::Jwt;
use crate::util::jwt::model::{JWTHeader, JWTPayload};
use crate::util::key_verification::KeyVerification;

/// JWT authorization token for use of authenticated holder/verifier access (LVVC fetching, remote trust-entity)
pub(crate) async fn prepare_bearer_token(
    did: &Did,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, ServiceError> {
    let authentication_key = did
        .find_first_matching_key(&KeyFilter::role_filter(KeyRole::Authentication))?
        .ok_or(ValidationError::KeyNotFound)?;

    let key_algorithm = authentication_key
        .key_algorithm_type()
        .and_then(|alg| key_algorithm_provider.key_algorithm_from_type(alg))
        .ok_or(ServiceError::MissingProvider(
            MissingProviderError::KeyAlgorithmProvider(
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                    authentication_key.key_type.to_owned(),
                ),
            ),
        ))?;

    let algorithm = key_algorithm
        .issuance_jose_alg_id()
        .ok_or(ServiceError::MappingError("Missing JOSE alg".to_string()))?
        .to_owned();

    let payload = JWTPayload {
        issuer: Some(did.did.to_string()),
        custom: BearerTokenPayload {
            timestamp: OffsetDateTime::now_utc(),
        },
        ..Default::default()
    };

    let key_id = did_method_provider
        .get_verification_method_id_from_did_and_key(did, authentication_key)
        .await?;

    let signer = key_provider.get_signature_provider(
        authentication_key,
        None,
        key_algorithm_provider.clone(),
    )?;
    let bearer_token = Jwt::<BearerTokenPayload> {
        header: JWTHeader {
            algorithm,
            key_id: Some(key_id),
            r#type: None,
            jwk: None,
            jwt: None,
            x5c: None,
        },
        payload,
    }
    .tokenize(Some(signer))
    .await?;

    Ok(bearer_token)
}

/// Validation of the bearer token signature and timestamp freshness
pub(crate) async fn validate_bearer_token(
    bearer_token: &str,
    did_method_provider: Arc<dyn DidMethodProvider>,
    key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    certificate_validator: Arc<dyn CertificateValidator>,
) -> Result<Jwt<BearerTokenPayload>, ServiceError> {
    let token_signature_verification = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::Authentication,
        certificate_validator,
    });

    let jwt: Jwt<BearerTokenPayload> = Jwt::build_from_token(
        bearer_token,
        Some(&(token_signature_verification as Box<dyn TokenVerifier>)),
        None,
    )
    .await?;

    // checking timestamp to prevent replay attack
    validate_expiration_time(&Some(jwt.payload.custom.timestamp), 60)
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
