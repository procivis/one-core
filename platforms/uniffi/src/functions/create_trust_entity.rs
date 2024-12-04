use crate::error::BindingError;
use crate::{CreateTrustEntityRequestBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_trust_entity(
        &self,
        request: CreateTrustEntityRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            let id = core
                .trust_entity_service
                .create_trust_entity(request)
                .await?;
            Ok(id.to_string())
        })
    }
}
