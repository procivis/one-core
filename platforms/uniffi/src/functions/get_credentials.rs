use crate::{
    error::BindingError, utils::into_id, CredentialListBindingDTO, CredentialListQueryBindingDTO,
    OneCoreBinding,
};
use one_core::{
    model::{list_filter::ListFilterValue, list_query::ListPagination},
    service::credential::dto::{CredentialFilterValue, GetCredentialQueryDTO},
};

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let condition = {
                let organisation =
                    CredentialFilterValue::OrganisationId(into_id(&query.organisation_id)?)
                        .condition();

                let role = query
                    .role
                    .map(|role| CredentialFilterValue::Role(role.into()));

                let ids = match query.ids {
                    Some(ids) => {
                        let ids = ids
                            .iter()
                            .map(|id| into_id(id))
                            .collect::<Result<Vec<_>, _>>()?;
                        Some(CredentialFilterValue::CredentialIds(ids))
                    }
                    None => None,
                };

                organisation & role & ids
            };

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
