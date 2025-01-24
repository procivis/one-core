use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_organisation(&self, uuid: Option<String>) -> Result<String, BindingError> {
        let id = match uuid {
            None => None,
            Some(uuid_str) => Some(into_id(&uuid_str)?),
        };

        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .create_organisation(id)
            .await?
            .to_string())
    }
}
