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

    pub fn version() -> Version {
        use shadow_rs::shadow;

        shadow!(build);

        Version {
            target: build::BUILD_RUST_CHANNEL.to_owned(),
            build_time: build::BUILD_TIME_3339.to_owned(),
            branch: build::BRANCH.to_owned(),
            tag: build::TAG.to_owned(),
            commit: build::COMMIT_HASH.to_owned(),
            rust_version: build::RUST_VERSION.to_owned(),
            pipeline_id: build::CI_PIPELINE_ID.to_owned(),
        }
    }
}

pub struct Version {
    pub target: String,
    pub build_time: String,
    pub branch: String,
    pub tag: String,
    pub commit: String,
    pub rust_version: String,
    pub pipeline_id: String,
}
