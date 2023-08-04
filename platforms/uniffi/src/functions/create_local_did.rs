use crate::{utils::run_sync, OneCore};

use one_core::data_layer::data_model::{CreateDidRequest, DidMethod, DidType};

pub use one_core::data_layer::DataLayerError;

impl OneCore {
    pub fn create_local_did(
        &self,
        did: String,
        organisation_id: String,
    ) -> Result<String, DataLayerError> {
        run_sync(async {
            Ok(self
                .inner
                .data_layer
                .create_did(CreateDidRequest {
                    name: "local".to_string(),
                    organisation_id,
                    did,
                    did_type: DidType::Local,
                    did_method: DidMethod::Key,
                })
                .await
                .map(|response| response.id)?)
        })
    }
}
