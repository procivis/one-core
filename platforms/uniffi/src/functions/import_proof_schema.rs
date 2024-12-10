use crate::binding::OneCoreBinding;
use crate::error::BindingError;
use crate::ImportProofSchemaRequestBindingsDTO;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestBindingsDTO,
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
