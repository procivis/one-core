use std::sync::Arc;

use crate::sts_token_validator::{StsJwksFetcher, StsJwksFetcherError, StsTokenValidator};
use crate::{AuthMode, ServerConfig};

#[derive(Clone)]
pub(crate) enum Authentication {
    None,
    Static(String),
    SecurityTokenService(StsTokenValidator),
}

pub(crate) async fn authentication(
    config: &Arc<ServerConfig>,
) -> Result<Authentication, StsJwksFetcherError> {
    match &config.auth {
        AuthMode::InsecureNone => Ok(Authentication::None),
        AuthMode::Static { static_token } => Ok(Authentication::Static(static_token.clone())),
        AuthMode::SecurityTokenService {
            sts_token_validation,
        } => {
            let reqwest_client = reqwest::Client::builder()
                .https_only(!config.allow_insecure_http_transport)
                .build()
                .expect("Failed to create reqwest::Client");

            let config = Arc::new(sts_token_validation.clone());
            let fetcher = Arc::new(StsJwksFetcher::new(reqwest_client, config.clone(), 3));
            let jwks = fetcher.fetch_jwks_with_retries().await?;
            let jwks_store = Arc::new(tokio::sync::RwLock::new(Arc::new(jwks)));
            Ok(Authentication::SecurityTokenService(
                StsTokenValidator::new(jwks_store, fetcher, config),
            ))
        }
    }
}
