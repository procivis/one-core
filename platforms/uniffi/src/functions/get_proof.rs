use crate::{dto::ProofRequestBindingDTO, error::BindingError, utils::into_id, OneCoreBinding};

impl OneCoreBinding {
    pub fn get_proof(&self, proof_id: String) -> Result<ProofRequestBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let proof = core.proof_service.get_proof(&into_id(&proof_id)?).await?;
            Ok(proof.into())
        })
    }
}
