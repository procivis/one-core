use one_core::service::error::ServiceError;
use serde_json::to_string;

use super::OneCore;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    #[uniffi::method]
    pub async fn run_task(
        &self,
        task: String,
        params: Option<String>,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        let params = params
            .map(|p| serde_json::from_str(&p))
            .transpose()
            .map_err(|err| {
                BindingError::from(ServiceError::Other(format!(
                    "Error parsing task params: {}",
                    err
                )))
            })?;
        let run_task = core.task_service.run(&task.into(), params).await?;
        to_string(&run_task)
            .map_err(|_| ServiceError::Other("Error serializing json".to_string()).into())
    }
}
