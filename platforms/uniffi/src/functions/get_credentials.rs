use crate::{
    error::BindingError, utils::into_uuid, CredentialListBindingDTO, ListQueryBindingDTO,
    OneCoreBinding,
};
use one_core::{
    model::{list_filter::ListFilterValue, list_query::ListPagination},
    service::credential::dto::{CredentialFilterValue, GetCredentialQueryDTO},
};

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: &ListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            let condition =
                CredentialFilterValue::OrganisationId(into_uuid(&query.organisation_id)?)
                    .condition()
                    & query
                        .role
                        .clone()
                        .map(|role| CredentialFilterValue::Role(role.into()));
            Ok(core
                .credential_service
                .get_credential_list(GetCredentialQueryDTO {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    sorting: None,
                    filtering: Some(condition),
                })
                .await?
                .into())
        })
    }
}
