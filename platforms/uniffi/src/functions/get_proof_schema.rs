use one_core::model::proof_schema::ProofSchemaId;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::{GetProofSchemaBindingDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn get_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<GetProofSchemaBindingDTO, BindingError> {
        let id: ProofSchemaId = into_id(&proof_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .get_proof_schema(&id)
                .await?
                .into())
        })
    }
}
