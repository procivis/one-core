use super::JsonLdService;
use crate::error::ContextWithErrorCode;
use crate::service::error::ServiceError;

impl JsonLdService {
    pub async fn resolve_context(&self, url: String) -> Result<serde_json::Value, ServiceError> {
        let (context, _) = &self
            .caching_loader
            .get(&url, self.resolver.clone(), false)
            .await
            .error_while("resolving JSON-LD context")?;
        serde_json::from_slice(context).map_err(|err| ServiceError::Other(err.to_string()))
    }
}
