use crate::error::BindingError;
use crate::utils::into_id;
use crate::{OneCoreBinding, ProposeProofResponseBindingDTO};

impl OneCoreBinding {
    pub fn propose_proof(
        &self,
        exchange: String,
        organisation_id: String,
    ) -> Result<ProposeProofResponseBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_service
                .propose_proof(exchange, into_id(&organisation_id)?)
                .await?
                .into())
        })
    }
}
