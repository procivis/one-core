use std::sync::Arc;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::common_validator::validate_expiration_time;
use crate::model::did::{Did, KeyRole};
use crate::provider::credential_formatter::jwt::model::{JWTHeader, JWTPayload};
use crate::provider::credential_formatter::jwt::Jwt;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::service::error::{MissingProviderError, ServiceError};
use crate::util::key_verification::KeyVerification;
use crate::KeyProvider;

/// JWT authorization token for use of authenticated holder/verifier access (LVVC fetching, remote trust-entity)
pub(crate) async fn prepare_bearer_token(
    did: &Did,
    key_provider: &dyn KeyProvider,
    key_algorithm_provider: &Arc<dyn KeyAlgorithmProvider>,
    did_method_provider: &dyn DidMethodProvider,
) -> Result<String, ServiceError> {
    let authentication_key = did.find_first_key_by_role(KeyRole::Authentication)?;

    let key_algorithm = key_algorithm_provider
        .get_key_algorithm(&authentication_key.key_type)
        .ok_or(ServiceError::MissingProvider(
            MissingProviderError::KeyAlgorithmProvider(
                KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                    authentication_key.key_type.to_owned(),
                ),
            ),
        ))?;

    let algorithm = key_algorithm
        .jose_alg()
        .first()
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
) -> Result<Jwt<BearerTokenPayload>, ServiceError> {
    let token_signature_verification = Box::new(KeyVerification {
        key_algorithm_provider,
        did_method_provider,
        key_role: KeyRole::Authentication,
    });

    let jwt: Jwt<BearerTokenPayload> =
        Jwt::build_from_token(bearer_token, Some(token_signature_verification)).await?;

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
