use crate::{
    error::BindingError, CredentialSchemaListBindingDTO, ListQueryBindingDTO, OneCoreBinding,
};
use one_core::service::credential_schema::dto::GetCredentialSchemaQueryDTO;

impl OneCoreBinding {
    pub fn get_credential_schemas(
        &self,
        query: ListQueryBindingDTO,
    ) -> Result<CredentialSchemaListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .get_credential_schema_list(GetCredentialSchemaQueryDTO {
                    page: query.page,
                    page_size: query.page_size,
                    sort: None,
                    sort_direction: None,
                    name: None,
                    organisation_id: query.organisation_id,
                    exact: None,
                })
                .await?
                .into())
        })
    }
}
