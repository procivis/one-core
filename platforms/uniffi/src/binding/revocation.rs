use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use one_dto_mapper::{convert_inner, From};

use super::credential::CredentialStateBindingEnum;
use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn check_revocation(
        &self,
        credential_ids: Vec<String>,
        force_refresh: Option<bool>,
    ) -> Result<Vec<CredentialRevocationCheckResponseBindingDTO>, BindingError> {
        let core = self.use_core().await?;
        Ok(convert_inner(
            core.credential_service
                .check_revocation(
                    credential_ids
                        .iter()
                        .map(|id| into_id(id))
                        .collect::<Result<Vec<_>, _>>()?,
                    force_refresh.unwrap_or_default(),
                )
                .await?,
        ))
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialRevocationCheckResponseDTO)]
pub struct CredentialRevocationCheckResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub credential_id: String,
    pub status: CredentialStateBindingEnum,
    pub success: bool,
    pub reason: Option<String>,
}
