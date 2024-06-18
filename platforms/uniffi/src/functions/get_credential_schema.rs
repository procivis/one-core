use crate::{
    error::BindingError, utils::into_id, CredentialSchemaDetailBindingDTO, OneCoreBinding,
};
use shared_types::CredentialSchemaId;

impl OneCoreBinding {
    pub fn get_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<CredentialSchemaDetailBindingDTO, BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .get_credential_schema(&credential_schema_id)
                .await?
                .into())
        })
    }
}
