use std::sync::Arc;

pub(crate) use fetcher::{StsJwksFetcher, StsJwksFetcherError};
use tokio::sync::RwLock;
pub(crate) use validator::StsTokenValidator;

pub(crate) use crate::sts_token_validator::model::Jwks;

pub(crate) type JwksStore = Arc<RwLock<Arc<Jwks>>>;

mod validator {
    use std::fmt::Debug;
    use std::sync::Arc;

    use one_core::proto::jwt::Jwt;
    use one_core::proto::jwt::model::{DecomposedJwt, JWTPayload};
    use one_core::provider::credential_formatter::error::FormatterError;
    use one_core::validator::{
        validate_audience, validate_expiration_time, validate_not_before_time,
    };
    use one_crypto::SignerError;
    use serde::de::DeserializeOwned;
    use thiserror::Error;
    use tokio::sync::Mutex;

    use crate::StsTokenValidation;
    use crate::sts_token_validator::model::Jwks;
    use crate::sts_token_validator::{JwksStore, StsJwksFetcher};

    #[derive(Clone)]
    pub struct StsTokenValidator {
        config: Arc<StsTokenValidation>,
        jwks_store: JwksStore,
        fetcher: Arc<StsJwksFetcher>,
        fetch_lock: Arc<Mutex<()>>,
    }

    impl StsTokenValidator {
        pub(crate) fn new(
            jwks_store: JwksStore,
            fetcher: Arc<StsJwksFetcher>,
            config: Arc<StsTokenValidation>,
        ) -> Self {
            Self {
                config,
                fetcher,
                jwks_store,
                fetch_lock: Arc::new(Default::default()),
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
                self.config.leeway,
            )?;
            let jwks = self.get_jwks().await;
            let matching_key = jwks.find_by_kid(kid);
            let Some(matching_key) = matching_key else {
                return Err(StsError::NoMatchingKey);
            };

            matching_key
                .verify(jwt.unverified_jwt.as_ref(), jwt.signature.as_ref())
                .map_err(StsError::FailedToVerifySignature)?;
            Ok(jwt)
        }

        async fn get_jwks(&self) -> Arc<Jwks> {
            let jwks = self.jwks_store.read().await.clone();
            if jwks.has_expired() {
                let fetch_lock = self.fetch_lock.clone();
                let fetcher_clone = self.fetcher.clone();
                let jwks_store_clone = self.jwks_store.clone();
                tokio::spawn(async move {
                    if let Ok(_lock) = fetch_lock.try_lock() {
                        match fetcher_clone.fetch_jwks_with_retries().await {
                            Ok(jwks) => {
                                let mut guard = jwks_store_clone.write().await;
                                *guard = Arc::new(jwks);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to update jwks: {e}");
                            }
                        };
                    } else {
                        // another task is already fetching, can skip
                    }
                });
            }
            jwks
        }
    }

    fn validate_token<V>(
        expected_aud: &str,
        expected_iss: &str,
        payload: &JWTPayload<V>,
        leeway: u64,
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
        validate_expiration_time(&Some(expires_at), leeway).map_err(|_| StsError::ExpiredToken)?;

        validate_not_before_time(&payload.invalid_before, leeway)
            .map_err(|_| StsError::NotBeforeToken)?;
        Ok(())
    }

    #[derive(Error, Debug)]
    pub(crate) enum StsError {
        #[error("Empty token.")]
        EmptyToken,
        #[error("Failed to decode JWT. Cause: {0}.")]
        FailedToDecodeJwt(FormatterError),
        #[error("Unsupported algorithm.")]
        UnsupportedAlgorithm,
        #[error("Missing key id.")]
        MissingKid,
        #[error("No matching key found.")]
        NoMatchingKey,
        #[error("Failed to verify token signature. Cause: {0}.")]
        FailedToVerifySignature(SignerError),
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
        #[error("Expired token.")]
        ExpiredToken,
        #[error("Not before token.")]
        NotBeforeToken,
    }
}

mod fetcher {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use one_core::model::key::PublicKeyJwk;
    use one_core::provider::key_algorithm::KeyAlgorithm;
    use one_core::provider::key_algorithm::eddsa::Eddsa;
    use one_core::provider::key_algorithm::error::KeyAlgorithmError;
    use thiserror::Error;
    use time::OffsetDateTime;

    use crate::StsTokenValidation;
    use crate::sts_token_validator::model::Jwks;

    #[derive(Debug, Error)]
    pub(crate) enum StsJwksFetcherError {
        #[error("Retries exceeded cause: {error:?}")]
        RetriesExceeded { error: Option<reqwest::Error> },
        #[error("Failed to parse JWK. Cause: {0}.")]
        FailedToParseJWK(KeyAlgorithmError),
    }

    pub(crate) struct StsJwksFetcher {
        http_client: reqwest::Client,
        config: Arc<StsTokenValidation>,
        max_retries: u32,
    }

    impl StsJwksFetcher {
        pub(crate) fn new(
            http_client: reqwest::Client,
            config: Arc<StsTokenValidation>,
            max_retries: u32,
        ) -> Self {
            Self {
                http_client,
                config,
                max_retries,
            }
        }

        pub(crate) async fn fetch_jwks_with_retries(&self) -> Result<Jwks, StsJwksFetcherError> {
            let mut retries = 0;
            let mut last_error = None;
            loop {
                if retries > self.max_retries {
                    tracing::error!("Retries exceeded for fetch jwks: {last_error:?}");
                    return Err(StsJwksFetcherError::RetriesExceeded { error: last_error });
                }
                match self.fetch_jwks().await {
                    Ok(jwks) => {
                        let keys = jwks
                            .keys
                            .iter()
                            .filter_map(|k| k.kid().map(|kid| (kid.to_string(), k)))
                            .map(|(kid, v)| Eddsa.parse_jwk(v).map(|kh| (kid, kh)))
                            .collect::<Result<HashMap<_, _>, _>>()
                            .map_err(StsJwksFetcherError::FailedToParseJWK)?;
                        let now = OffsetDateTime::now_utc();
                        return Ok(Jwks {
                            ttl: now + Duration::from_secs(self.config.ttl_jwks),
                            keys,
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Failed to fetch jwks: {e}");
                        tokio::time::sleep(Duration::from_secs((retries as f32).powf(1.5) as u64))
                            .await;
                        retries += 1;
                        last_error = Some(e);
                    }
                }
            }
        }

        async fn fetch_jwks(&self) -> Result<JwksDTO, reqwest::Error> {
            self.http_client
                .get(self.config.jwks_uri.clone())
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
        keys: Vec<PublicKeyJwk>,
    }
}

mod model {
    use std::collections::HashMap;

    use one_core::provider::key_algorithm::key::KeyHandle;
    use time::OffsetDateTime;

    pub(crate) struct Jwks {
        pub ttl: OffsetDateTime,
        pub keys: HashMap<String, KeyHandle>,
    }

    impl Jwks {
        pub(crate) fn find_by_kid(&self, kid: &str) -> Option<&KeyHandle> {
            self.keys.get(kid)
        }

        pub(crate) fn has_expired(&self) -> bool {
            self.ttl < OffsetDateTime::now_utc()
        }
    }
}
