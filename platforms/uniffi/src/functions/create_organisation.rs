use crate::{
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn create_organisation(&self, uuid: Option<String>) -> Result<String, ServiceError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(into_uuid(&uuid_str)?),
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
