use shared_types::ProofSchemaId;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn delete_proof_schema(&self, proof_schema_id: String) -> Result<(), BindingError> {
        let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .delete_proof_schema(&proof_schema_id)
                .await?)
        })
    }
}
