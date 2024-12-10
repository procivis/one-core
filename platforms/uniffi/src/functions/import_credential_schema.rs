use crate::binding::OneCoreBinding;
use crate::dto::ImportCredentialSchemaRequestBindingDTO;
use crate::error::BindingError;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .import_credential_schema(request)
                .await
                .map(|schema| schema.to_string())?)
        })
    }
}
