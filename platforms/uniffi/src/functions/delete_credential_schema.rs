use shared_types::CredentialSchemaId;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn delete_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<(), BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .delete_credential_schema(&credential_schema_id)
                .await?)
        })
    }
}
