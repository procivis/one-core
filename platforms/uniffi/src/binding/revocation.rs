use one_core::model::cache::CachePreferences;
use one_core::service::credential::dto::CredentialRevocationCheckResponseDTO;
use one_dto_mapper::{convert_inner, From, Into};

use super::credential::CredentialStateBindingEnum;
use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn check_revocation(
        &self,
        credential_ids: Vec<String>,
        bypass_cache: Option<Vec<BypassCacheBindingDTO>>,
    ) -> Result<Vec<CredentialRevocationCheckResponseBindingDTO>, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let cache_preferences = bypass_cache.map(|vec| CachePreferences {
                bypass: convert_inner(vec),
            });
            Ok(convert_inner(
                core.credential_service
                    .check_revocation(
                        credential_ids
                            .iter()
                            .map(|id| into_id(id))
                            .collect::<Result<Vec<_>, _>>()?,
                        cache_preferences,
                    )
                    .await?,
            ))
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Into, uniffi::Enum)]
#[into("one_core::model::remote_entity_cache::CacheType")]
pub enum BypassCacheBindingDTO {
    DidDocument,
    StatusListCredential,
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
