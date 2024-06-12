use crate::{
    error::BindingError, utils::into_id, CredentialSchemaListBindingDTO,
    CredentialSchemaListQueryBindingDTO, CredentialSchemaListQueryExactColumnBindingEnum,
    OneCoreBinding,
};
use one_core::{
    model::{
        list_filter::{ListFilterCondition, ListFilterValue, StringMatch},
        list_query::{ListPagination, ListSorting},
    },
    service::credential_schema::dto::{CredentialSchemaFilterValue, GetCredentialSchemaQueryDTO},
};

impl OneCoreBinding {
    pub fn get_credential_schemas(
        &self,
        query: CredentialSchemaListQueryBindingDTO,
    ) -> Result<CredentialSchemaListBindingDTO, BindingError> {
        let sorting = query.sort.map(|sort_by| ListSorting {
            column: sort_by.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let mut conditions =
            vec![
                CredentialSchemaFilterValue::OrganisationId(into_id(&query.organisation_id)?)
                    .condition(),
            ];

        if let Some(name) = query.name {
            let name_filter = if query
                .exact
                .is_some_and(|e| e.contains(&CredentialSchemaListQueryExactColumnBindingEnum::Name))
            {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            conditions.push(CredentialSchemaFilterValue::Name(name_filter).condition())
        }

        if let Some(ids) = query.ids {
            let ids = ids.iter().map(|id| into_id(id)).collect::<Result<_, _>>()?;
            conditions.push(CredentialSchemaFilterValue::CredentialSchemaIds(ids).condition());
        }

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .credential_schema_service
                .get_credential_schema_list(GetCredentialSchemaQueryDTO {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    filtering: Some(ListFilterCondition::And(conditions)),
                    sorting,
                    include: query
                        .include
                        .map(|incl| incl.into_iter().map(Into::into).collect()),
                })
                .await?
                .into())
        })
    }
}
