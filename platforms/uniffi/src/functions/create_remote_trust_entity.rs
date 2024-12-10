use crate::error::BindingError;
use crate::{CreateRemoteTrustEntityRequestBindingDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn create_remote_trust_entity(
        &self,
        request: CreateRemoteTrustEntityRequestBindingDTO,
    ) -> Result<String, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .trust_entity_service
                .create_remote_trust_entity_for_did(request.try_into()?)
                .await?
                .to_string())
        })
    }
}
