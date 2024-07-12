use crate::{error::BindingError, utils::into_id, OneCoreBinding};

impl OneCoreBinding {
    pub fn retract_proof(&self, proof_id: String) -> Result<String, BindingError> {
        let proof_id = into_id(&proof_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            let response = core.proof_service.retract_proof(proof_id).await?;

            Ok(response.to_string())
        })
    }
}
