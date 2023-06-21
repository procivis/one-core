#![cfg_attr(feature = "strict", deny(warnings))]

use std::sync::Arc;

use one_core::data_layer::data_model::CreateOrganisationRequest;
use tokio::runtime::Runtime;

uniffi::include_scaffolding!("one_core");

pub struct OneCore {
    inner: one_core::OneCore,
}

pub type Version = one_core::Version;

impl OneCore {
    fn create_org(&self) -> String {
        let rt = Runtime::new().unwrap();
        let org = rt.block_on(async {
            self.inner
                .data_layer
                .create_organisation(CreateOrganisationRequest { id: None })
                .await
        });
        match org {
            Ok(org) => org.id,
            Err(_) => "Error".to_string(),
        }
    }

    fn version(&self) -> Version {
        one_core::OneCore::version()
    }
}

fn initialize_core() -> Arc<OneCore> {
    let rt = Runtime::new().unwrap();
    let core = rt.block_on(async { one_core::OneCore::new("sqlite::memory:").await });
    Arc::new(OneCore { inner: core })
}
