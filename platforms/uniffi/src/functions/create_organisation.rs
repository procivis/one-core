use crate::{utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn create_organisation(&self, uuid: Option<String>) -> Result<String, ServiceError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(
                Uuid::parse_str(&uuid_str)
                    .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?,
            ),
        };

        run_sync(async {
            self.inner
                .organisation_service
                .create_organisation(id)
                .await
                .map(|org| org.to_string())
        })
    }
}
