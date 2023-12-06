use crate::{error::BindingError, CredentialListBindingDTO, ListQueryBindingDTO, OneCoreBinding};
use one_core::service::credential::dto::GetCredentialQueryDTO;

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: &ListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_service
                .get_credential_list(GetCredentialQueryDTO {
                    page: query.page,
                    page_size: query.page_size,
                    sort: None,
                    exact: None,
                    sort_direction: None,
                    name: None,
                    organisation_id: query.organisation_id.to_owned(),
                })
                .await?
                .into())
        })
    }
}
