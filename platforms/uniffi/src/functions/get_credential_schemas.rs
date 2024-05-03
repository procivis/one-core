use crate::{
    error::BindingError, utils::into_id, CredentialSchemaListBindingDTO, ListQueryBindingDTO,
    OneCoreBinding,
};
use one_core::{
    model::{list_filter::ListFilterValue, list_query::ListPagination},
    service::credential_schema::dto::{CredentialSchemaFilterValue, GetCredentialSchemaQueryDTO},
};

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
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(into_id(
                            &query.organisation_id,
                        )?)
                        .condition(),
                    ),
                    ..Default::default()
                })
                .await?
                .into())
        })
    }
}
