use crate::{utils::run_sync, OneCore};

use one_core::data_layer::data_model::CreateOrganisationRequest;
use uuid::Uuid;

pub use one_core::data_layer::DataLayerError;

impl OneCore {
    pub fn create_organisation(&self, uuid: Option<String>) -> Result<String, DataLayerError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(
                Uuid::parse_str(&uuid_str)
                    .map_err(|e| DataLayerError::GeneralRuntimeError(e.to_string()))?,
            ),
        };

        run_sync(async {
            Ok(self
                .inner
                .data_layer
                .create_organisation(CreateOrganisationRequest { id })
                .await
                .map(|org| org.id)?)
        })
    }
}
