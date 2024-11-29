use one_core::service::error::ServiceError;
use serde_json::to_string;

use crate::error::BindingError;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn run_task(&self, task: String) -> Result<String, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let run_task = core.task_service.run(&task).await?;
            to_string(&run_task)
                .map_err(|_| ServiceError::Other("Error serializing json".to_string()).into())
        })
    }
}
