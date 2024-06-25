use crate::{error::BindingError, CreateProofRequestBindingDTO, OneCoreBinding};

impl OneCoreBinding {
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
