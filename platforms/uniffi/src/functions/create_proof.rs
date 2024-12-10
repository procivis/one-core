use crate::error::BindingError;
use crate::{CreateProofRequestBindingDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn create_proof(
        &self,
        request: CreateProofRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core.proof_service.create_proof(request).await?.to_string())
        })
    }
}
