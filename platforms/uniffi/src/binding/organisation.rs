use super::OneCore;
use super::mapper::OptionalString;
use crate::error::BindingError;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Creates an organization.
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

    /// Updates or deactivates an organization if it exists, otherwise
    /// creates a new organization using the provided UUID and name.
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
#[uniffi(name = "CreateOrganisationRequest")]
pub struct CreateOrganisationRequestBindingDTO {
    /// If no UUID is passed, one will be created.
    pub id: Option<String>,
    /// If no name is passed, the UUID will be used.
    pub name: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "UpsertOrganisationRequest")]
pub struct UpsertOrganisationRequestBindingDTO {
    /// Unique identifier of the organization to create or update.
    pub id: String,
    /// Organization's display name.
    pub name: Option<String>,
    /// Set to `true` to deactivate the organization.
    pub deactivate: Option<bool>,
    /// Wallet Provider use only.
    pub wallet_provider: Option<OptionalString>,
    /// Wallet Provider use only.
    pub wallet_provider_issuer: Option<OptionalString>,
}
