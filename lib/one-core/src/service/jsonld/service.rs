use super::JsonLdService;
use crate::service::error::ServiceError;

impl JsonLdService {
    pub async fn resolve_context(&self, url: String) -> Result<serde_json::Value, ServiceError> {
        serde_json::from_str(
            &self
                .caching_loader
                .load_context(&url)
                .await
                .map_err(|err| ServiceError::Other(err.to_string()))?,
        )
        .map_err(|err| ServiceError::Other(err.to_string()))
    }
}
