use one_core::service::error::ServiceError;
use serde_json::to_string;

use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn run_task(&self, task: String) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        let run_task = core.task_service.run(&task).await?;
        to_string(&run_task)
            .map_err(|_| ServiceError::Other("Error serializing json".to_string()).into())
    }
}
