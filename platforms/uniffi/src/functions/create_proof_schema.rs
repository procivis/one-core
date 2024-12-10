use crate::error::BindingError;
use crate::{CreateProofSchemaRequestDTO, OneCoreBinding};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
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
