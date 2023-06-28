#![cfg_attr(feature = "strict", deny(warnings))]

use data_layer::DataLayer;

pub mod data_layer;

// Clone just for now. Later it should be removed.
#[derive(Clone)]
pub struct OneCore {
    pub data_layer: DataLayer,
}

impl OneCore {
    pub async fn new(database_url: &str) -> OneCore {
        OneCore {
            data_layer: DataLayer::create(database_url).await,
        }
    }
}
