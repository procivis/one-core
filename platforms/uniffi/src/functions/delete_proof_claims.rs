use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn delete_proof_claims(&self, proof_id: String) -> Result<(), BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            core.proof_service
                .delete_proof_claims(into_id(&proof_id)?)
                .await?;
            Ok(())
        })
    }
}
