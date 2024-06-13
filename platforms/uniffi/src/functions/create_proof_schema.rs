use crate::{error::BindingError, CreateProofSchemaRequestDTO, OneCoreBinding};

impl OneCoreBinding {
    pub fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequestDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .create_proof_schema(request)
                .await?
                .to_string())
        })
    }
}
