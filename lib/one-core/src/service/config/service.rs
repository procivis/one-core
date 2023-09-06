use super::{dto::ConfigDTO, ConfigService};
use crate::service::error::ServiceError;

impl ConfigService {
    pub fn get_config(&self) -> Result<ConfigDTO, ServiceError> {
        (&*self.config)
            .try_into()
            .map_err(|e: serde_json::Error| ServiceError::ValidationError(e.to_string()))
    }
}
