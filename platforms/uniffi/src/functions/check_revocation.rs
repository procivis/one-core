use one_core::model::cache::CachePreferences;
use one_dto_mapper::convert_inner;

use crate::dto::{BypassCacheBindingDTO, CredentialRevocationCheckResponseBindingDTO};
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

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
