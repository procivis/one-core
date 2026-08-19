use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{Value, json};

use super::Task;
use crate::error::ContextWithErrorCode;
use crate::provider::ecosystem::directory::EcosystemDirectory;
use crate::service::error::ServiceError;

pub(crate) struct EcosystemLifecycleCheckTask {
    ecosystem_directory: Arc<dyn EcosystemDirectory>,
}

impl EcosystemLifecycleCheckTask {
    pub fn new(ecosystem_directory: Arc<dyn EcosystemDirectory>) -> Self {
        Self {
            ecosystem_directory,
        }
    }
}

#[async_trait::async_trait]
impl Task for EcosystemLifecycleCheckTask {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let mut ecosystems = BTreeMap::new();

        for ecosystem in self.ecosystem_directory.enabled_ecosystems() {
            tracing::info!(
                "Running lifecycle check for ecosystem `{}`",
                ecosystem.config_name()
            );
            let result = ecosystem
                .lifecycle_hook()
                .await
                .error_while(format!("running lifecycle hook of {ecosystem}"))?;

            ecosystems.insert(ecosystem.config_name().to_owned(), result);
        }

        Ok(json!({ "ecosystems": ecosystems }))
    }
}
