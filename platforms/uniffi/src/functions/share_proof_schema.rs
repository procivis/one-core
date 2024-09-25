use shared_types::ProofSchemaId;

use crate::dto::ProofSchemaShareResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn share_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<ProofSchemaShareResponseBindingDTO, BindingError> {
        self.block_on(async {
            let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .share_proof_schema(proof_schema_id)
                .await?
                .into())
        })
    }
}
