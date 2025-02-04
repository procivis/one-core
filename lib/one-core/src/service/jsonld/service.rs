use super::JsonLdService;
use crate::service::error::ServiceError;

impl JsonLdService {
    pub async fn resolve_context(&self, url: String) -> Result<serde_json::Value, ServiceError> {
        let (context, _) = &self
            .caching_loader
            .get(&url, self.resolver.clone(), false)
            .await
            .map_err(|err| ServiceError::Other(err.to_string()))?;
        serde_json::from_slice(context).map_err(|err| ServiceError::Other(err.to_string()))
    }
}
