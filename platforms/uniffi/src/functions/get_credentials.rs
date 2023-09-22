use crate::{utils::run_sync, CredentialListBindingDTO, ListQueryBindingDTO, OneCoreBinding};
use one_core::service::{credential::dto::GetCredentialQueryDTO, error::ServiceError};

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: &ListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, ServiceError> {
        run_sync(async {
            Ok(self
                .inner
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
