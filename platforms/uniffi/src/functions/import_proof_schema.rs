use crate::{binding::OneCoreBinding, error::BindingError, ProofSchemaImportRequestDTO};

impl OneCoreBinding {
    pub fn import_proof_schema(
        &self,
        request: ProofSchemaImportRequestDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .import_proof_schema(request)
                .await
                .map(|schema| schema.id.to_string())?)
        })
    }
}
