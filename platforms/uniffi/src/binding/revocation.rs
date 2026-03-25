use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use one_dto_mapper::{From, convert_inner};

use super::OneCore;
use super::credential::CredentialStateBindingEnum;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Checks whether a held credential has been suspended or revoked.
    ///
    /// For list-based revocation methods, the signed lists and any DID
    /// documents containing public keys used to verify the lists are
    /// cached. Use `forceRefresh` to force the system to retrieve these
    /// from the external resource.
    ///
    /// For modcs, use `forceRefresh` to force the system to request a
    /// new MSO.
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
                        .map(into_id)
                        .collect::<Result<Vec<_>, _>>()?,
                    force_refresh.unwrap_or_default(),
                )
                .await?,
        ))
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialRevocationCheckResponseDTO)]
#[uniffi(name = "CredentialRevocationCheckResponse")]
pub struct CredentialRevocationCheckResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub credential_id: String,
    pub status: CredentialStateBindingEnum,
    pub success: bool,
    pub reason: Option<String>,
}
