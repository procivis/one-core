pub(crate) use fetcher::{StsJwksFetcher, StsJwksFetcherError};
pub(crate) use validator::StsTokenValidator;

mod validator {
    use std::fmt::Debug;
    use std::sync::Arc;

    use one_core::proto::jwt::model::{DecomposedJwt, JWTPayload};
    use one_core::proto::jwt::{Jwt, TokenError};
    use one_core::provider::key_algorithm::key::KeyHandleError;
    use one_core::validator::{
        TimestampValidationError, validate_audience, validate_expiration_time,
        validate_not_before_time,
    };
    use serde::de::DeserializeOwned;
    use thiserror::Error;
    use time::Duration;
    use tokio::sync::{Mutex, RwLock};

    use super::StsJwksFetcher;
    use super::model::Jwks;
    use crate::StsTokenValidation;

    type JwksStore = Arc<RwLock<Arc<Jwks>>>;

    #[derive(Clone)]
    pub struct StsTokenValidator {
        config: StsTokenValidation,
        jwks_store: JwksStore,
        fetch_lock: Arc<Mutex<StsJwksFetcher>>,
    }

    impl StsTokenValidator {
        pub(crate) fn new(jwks: Jwks, fetcher: StsJwksFetcher, config: StsTokenValidation) -> Self {
            Self {
                config,
                jwks_store: Arc::new(tokio::sync::RwLock::new(Arc::new(jwks))),
                fetch_lock: Arc::new(Mutex::new(fetcher)),
            }
        }

        pub(crate) async fn validate_sts_token<Payload: DeserializeOwned + Debug>(
            &self,
            token: &str,
        ) -> Result<DecomposedJwt<Payload>, StsError> {
            if token.is_empty() {
                return Err(StsError::EmptyToken);
            }

            let jwt =
                Jwt::<Payload>::decompose_token(token).map_err(StsError::FailedToDecodeJwt)?;
            if jwt.header.algorithm != "EdDSA" {
                return Err(StsError::UnsupportedAlgorithm);
            };
            let Some(kid) = &jwt.header.key_id else {
                return Err(StsError::MissingKid);
            };

            let payload = &jwt.payload;
            validate_token(
                &self.config.aud,
                &self.config.iss,
                payload,
                self.config.leeway_seconds,
            )?;
            let jwks = self.get_jwks().await?;
            let matching_key = jwks.find_by_kid(kid);
            let Some(matching_key) = matching_key else {
                return Err(StsError::NoMatchingKey);
            };

            matching_key
                .verify(jwt.unverified_jwt.as_ref(), jwt.signature.as_ref())
                .map_err(StsError::FailedToVerifySignature)?;
            Ok(jwt)
        }

        async fn get_jwks(&self) -> Result<Arc<Jwks>, StsError> {
            let jwks = self.jwks_store.read().await;

            let now = one_core::clock::now_utc();
            let expired = jwks.fetched_at + self.config.jwks_expire_after_seconds < now;
            let to_be_refreshed = jwks.fetched_at + self.config.jwks_refresh_after_seconds < now;

            if to_be_refreshed {
                let fetch_lock = self.fetch_lock.clone();
                let jwks_store_clone = self.jwks_store.clone();
                tokio::spawn(async move {
                    if let Ok(fetcher) = fetch_lock.try_lock() {
                        match fetcher.fetch_jwks_with_retries().await {
                            Ok(jwks) => {
                                let mut guard = jwks_store_clone.write().await;
                                *guard = Arc::new(jwks);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to update jwks: {e}");
                            }
                        };
                    } else {
                        tracing::debug!("Another task already fetching JWKs, skipping");
                    }
                });
            }

            if expired {
                tracing::error!("JWKs expired");
                return Err(StsError::ExpiredJWKs);
            }

            Ok(jwks.clone())
        }
    }

    fn validate_token<V>(
        expected_aud: &str,
        expected_iss: &str,
        payload: &JWTPayload<V>,
        leeway: Duration,
    ) -> Result<(), StsError> {
        let Some(ref p_issuer) = payload.issuer else {
            return Err(StsError::MissingIssuer);
        };
        if p_issuer != expected_iss {
            return Err(StsError::IncorrectIssuer);
        }

        let Some(ref audience) = payload.audience else {
            return Err(StsError::MissingAudience);
        };
        validate_audience(audience, expected_aud).map_err(|_| StsError::IncorrectAudience)?;

        let Some(expires_at) = payload.expires_at else {
            return Err(StsError::MissingExpirationDate);
        };
        validate_expiration_time(&Some(expires_at), leeway)?;
        validate_not_before_time(&payload.invalid_before, leeway)?;
        Ok(())
    }

    #[derive(Error, Debug)]
    pub(crate) enum StsError {
        #[error("Empty token.")]
        EmptyToken,
        #[error("Failed to decode JWT. Cause: {0}.")]
        FailedToDecodeJwt(TokenError),
        #[error("Unsupported algorithm.")]
        UnsupportedAlgorithm,
        #[error("Missing key id.")]
        MissingKid,
        #[error("No matching key found.")]
        NoMatchingKey,
        #[error("JWKs expired and cannot be refreshed.")]
        ExpiredJWKs,
        #[error("Failed to verify token signature. Cause: {0}.")]
        FailedToVerifySignature(KeyHandleError),
        #[error("Missing issuer.")]
        MissingIssuer,
        #[error("Incorrect issuer.")]
        IncorrectIssuer,
        #[error("Missing audience.")]
        MissingAudience,
        #[error("Incorrect audience.")]
        IncorrectAudience,
        #[error("Missing expiration date.")]
        MissingExpirationDate,
        #[error("Invalid token timestamp. Cause: {0}.")]
        InvalidTimestamp(#[from] TimestampValidationError),
    }
}

mod fetcher {
    use std::collections::HashMap;
    use std::time::Duration;

    use one_core::provider::key_algorithm::KeyAlgorithm;
    use one_core::provider::key_algorithm::eddsa::Eddsa;
    use one_core::provider::key_algorithm::error::KeyAlgorithmError;
    use standardized_types::jwk::PublicJwk;
    use thiserror::Error;

    use crate::StsTokenValidation;
    use crate::sts_token_validator::model::Jwks;

    #[derive(Debug, Error)]
    pub(crate) enum StsJwksFetcherError {
        #[error("Retries exceeded cause: {error}")]
        RetriesExceeded { error: reqwest::Error },
        #[error("Failed to parse JWK. Cause: {0}.")]
        FailedToParseJWK(KeyAlgorithmError),
    }

    pub(crate) struct StsJwksFetcher {
        http_client: reqwest::Client,
        config: StsTokenValidation,
        max_retries: u32,
    }

    impl StsJwksFetcher {
        pub(crate) fn new(
            http_client: reqwest::Client,
            config: StsTokenValidation,
            max_retries: u32,
        ) -> Self {
            Self {
                http_client,
                config,
                max_retries,
            }
        }

        pub(crate) async fn fetch_jwks_with_retries(&self) -> Result<Jwks, StsJwksFetcherError> {
            let mut attempt = 0;
            loop {
                match self.fetch_jwks().await {
                    Ok(jwks) => {
                        let keys = jwks
                            .keys
                            .iter()
                            .filter_map(|k| k.kid().map(|kid| (kid.to_string(), k)))
                            .map(|(kid, v)| Eddsa.parse_jwk(v).map(|kh| (kid, kh)))
                            .collect::<Result<HashMap<_, _>, _>>()
                            .map_err(StsJwksFetcherError::FailedToParseJWK)?;

                        return Ok(Jwks {
                            fetched_at: one_core::clock::now_utc(),
                            keys,
                        });
                    }
                    Err(error) => {
                        if attempt >= self.max_retries {
                            tracing::error!("Retries exceeded for fetch jwks: {error}");
                            return Err(StsJwksFetcherError::RetriesExceeded { error });
                        }

                        tracing::warn!("Failed to fetch jwks (attempt: {attempt}): {error}");
                        tokio::time::sleep(Duration::from_secs((attempt as f32).powf(1.5) as u64))
                            .await;
                        attempt += 1;
                    }
                }
            }
        }

        async fn fetch_jwks(&self) -> Result<JwksDTO, reqwest::Error> {
            self.http_client
                .get(&self.config.jwks_uri)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JwksDTO {
        keys: Vec<PublicJwk>,
    }
}

mod model {
    use std::collections::HashMap;

    use one_core::provider::key_algorithm::key::KeyHandle;
    use time::OffsetDateTime;

    pub(crate) struct Jwks {
        pub fetched_at: OffsetDateTime,
        pub keys: HashMap<String, KeyHandle>,
    }

    impl Jwks {
        pub(crate) fn find_by_kid(&self, kid: &str) -> Option<&KeyHandle> {
            self.keys.get(kid)
        }
    }
}
