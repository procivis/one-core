use super::OneCoreBinding;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn create_organisation(
        &self,
        request: CreateOrganisationRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .create_organisation(request.try_into()?)
            .await?
            .to_string())
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CreateOrganisationRequestBindingDTO {
    pub id: Option<String>,
    pub name: Option<String>,
}
