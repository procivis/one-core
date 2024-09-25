use shared_types::CredentialSchemaId;

use crate::dto::CredentialSchemaShareResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn share_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<CredentialSchemaShareResponseBindingDTO, BindingError> {
        self.block_on(async {
            let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .share_credential_schema(&credential_schema_id)
                .await?
                .into())
        })
    }
}
