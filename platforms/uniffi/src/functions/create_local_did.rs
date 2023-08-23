use one_core::repository::data_provider::{CreateDidRequest, DidType};

use crate::{utils::run_sync, OneCore};
pub use one_core::repository::error::DataLayerError;

impl OneCore {
    pub fn create_local_did(
        &self,
        did: String,
        organisation_id: String,
    ) -> Result<String, DataLayerError> {
        run_sync(async {
            self.inner
                .data_layer
                .create_did(
                    CreateDidRequest {
                        name: "local".to_string(),
                        organisation_id,
                        did,
                        did_type: DidType::Local,
                        method: "KEY".to_string(),
                    },
                    &self.inner.config.did,
                )
                .await
                .map(|response| response.id)
        })
    }
}
