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

    #[uniffi::method]
    pub async fn upsert_organisation(
        &self,
        request: UpsertOrganisationRequestBindingDTO,
    ) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .organisation_service
            .upsert_organisation(request.try_into()?)
            .await?)
    }
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CreateOrganisationRequestBindingDTO {
    pub id: Option<String>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct UpsertOrganisationRequestBindingDTO {
    pub id: String,
    pub name: Option<String>,
    pub deactivate: Option<bool>,
}
