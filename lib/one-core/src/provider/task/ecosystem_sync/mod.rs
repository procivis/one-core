use std::sync::Arc;

use InstanceFilterValue::Status;
use serde_json::{Value, json};

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::instance::{InstanceFilterValue, InstanceListQuery, InstanceStatus};
use crate::model::list_filter::ListFilterValue;
use crate::model::list_query::ListPagination;
use crate::proto::ecosystem_sync::EcosystemSync;
use crate::provider::task::Task;
use crate::repository::instance_repository::InstanceRepository;
use crate::service::error::ServiceError;

#[cfg(test)]
mod test;

pub(crate) struct EcosystemSyncTask {
    instance_repository: Arc<dyn InstanceRepository>,
    ecosystem_sync: Arc<dyn EcosystemSync>,
}

#[derive(Debug, thiserror::Error)]
pub enum EcosystemSyncError {
    #[error("Invalid task params: {0}")]
    InvalidParams(#[from] serde_json::Error),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for EcosystemSyncError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidParams(_) => ErrorCode::BR_0405,
            Self::Nested(nested_error) => nested_error.error_code(),
        }
    }
}

#[async_trait::async_trait]
impl Task for EcosystemSyncTask {
    async fn run(&self, _params: Option<Value>) -> Result<Value, ServiceError> {
        let result = self
            .run_internal()
            .await
            .error_while("syncing ecosystems")?;
        Ok(result)
    }
}

impl EcosystemSyncTask {
    pub fn new(
        instance_repository: Arc<dyn InstanceRepository>,
        ecosystem_sync: Arc<dyn EcosystemSync>,
    ) -> Self {
        Self {
            instance_repository,
            ecosystem_sync,
        }
    }

    async fn run_internal(&self) -> Result<Value, EcosystemSyncError> {
        let synced_collections_count = self.sync_instance_collections().await?;
        Ok(json!({
            "syncedTrustCollectionsCount": synced_collections_count,
        }))
    }

    async fn sync_instance_collections(&self) -> Result<usize, EcosystemSyncError> {
        let mut count = 0;
        let mut page = 0;
        loop {
            let instances = self
                .instance_repository
                .list(InstanceListQuery {
                    include_count: false,
                    pagination: Some(ListPagination {
                        page,
                        page_size: 1000,
                    }),
                    filtering: Some(
                        Status(InstanceStatus::Active).condition()
                            | Status(InstanceStatus::Unattested),
                    ),
                    ..Default::default()
                })
                .await
                .error_while("listing holder wallet instances")?;
            if instances.values.is_empty() {
                break;
            }
            for instance in instances.values {
                count += self.ecosystem_sync.sync_instance(&instance).await?;
            }
            page += 1;
        }
        Ok(count)
    }
}
