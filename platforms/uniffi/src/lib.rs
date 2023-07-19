#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;

use one_core::data_layer::{data_model::CreateOrganisationRequest, DataLayerError};
use tokio::runtime::Runtime;

uniffi::include_scaffolding!("one_core");

pub struct OneCore {
    inner: one_core::OneCore,
}

pub type Version = one_core::Version;

impl OneCore {
    fn create_org(&self) -> Result<String, DataLayerError> {
        let rt = Runtime::new().unwrap();
        let org_response = rt.block_on(async {
            self.inner
                .data_layer
                .create_organisation(CreateOrganisationRequest { id: None })
                .await
        });
        org_response.map(|org| org.id)
    }

    fn version(&self) -> Version {
        one_core::OneCore::version()
    }
}

fn initialize_core(data_dir_path: String) -> Arc<OneCore> {
    let rt = Runtime::new().unwrap();
    let core = rt.block_on(async {
        one_core::OneCore::new(
            format!("sqlite:{data_dir_path}/one_core_db.sqlite?mode=rwc").as_str(),
        )
        .await
    });
    Arc::new(OneCore { inner: core })
}
