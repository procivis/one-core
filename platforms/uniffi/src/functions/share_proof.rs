use crate::{error::BindingError, utils::into_id, OneCoreBinding, ShareProofResponseBindingDTO};

impl OneCoreBinding {
    pub fn share_proof(
        &self,
        proof_id: String,
    ) -> Result<ShareProofResponseBindingDTO, BindingError> {
        let request = into_id(&proof_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            let response = core.proof_service.share_proof(&request).await?;

            Ok(ShareProofResponseBindingDTO::from(response))
        })
    }
}
