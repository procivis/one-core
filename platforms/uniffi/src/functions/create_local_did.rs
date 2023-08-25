use std::str::FromStr;

use one_core::{model::did::DidType, service::did::dto::CreateDidRequestDTO};
use uuid::Uuid;

use crate::{utils::run_sync, OneCore};
pub use one_core::service::error::ServiceError;

impl OneCore {
    pub fn create_local_did(
        &self,
        did: String,
        organisation_id: String,
    ) -> Result<String, ServiceError> {
        run_sync(async {
            self.inner
                .did_service
                .create_did(CreateDidRequestDTO {
                    name: "local".to_string(),
                    organisation_id: Uuid::from_str(&organisation_id)
                        .map_err(|e| ServiceError::MappingError(e.to_string()))?,
                    did,
                    did_type: DidType::Local,
                    did_method: "KEY".to_string(),
                })
                .await
                .map(|id| id.to_string())
        })
    }
}
