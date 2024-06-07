use crate::{error::BindingError, OneCoreBinding, ProofListBindingDTO, ProofListQueryBindingDTO};

impl OneCoreBinding {
    pub fn get_proofs(
        &self,
        query: ProofListQueryBindingDTO,
    ) -> Result<ProofListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let proofs = core.proof_service.get_proof_list(query.try_into()?).await?;
            Ok(proofs.into())
        })
    }
}
