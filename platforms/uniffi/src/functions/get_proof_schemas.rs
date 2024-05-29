use crate::error::BindingError;
use crate::{ListProofSchamasFiltersBindingDTO, OneCoreBinding, ProofSchemaListBindingDTO};

impl OneCoreBinding {
    pub fn get_proof_schemas(
        &self,
        filter: ListProofSchamasFiltersBindingDTO,
    ) -> Result<ProofSchemaListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .get_proof_schema_list(filter.try_into()?)
                .await?
                .into())
        })
    }
}
