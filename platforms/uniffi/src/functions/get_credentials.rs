use dto_mapper::convert_inner;
use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::{
    CredentialFilterValue, GetCredentialQueryDTO, GetCredentialQueryFiltersDTO,
};

use crate::error::BindingError;
use crate::utils::into_id;
use crate::{
    CredentialListBindingDTO, CredentialListQueryBindingDTO,
    CredentialListQueryExactColumnBindingEnum, OneCoreBinding,
};

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let condition = {
                let exact = query.exact.unwrap_or_default();
                let get_string_match_type = |column| {
                    if exact.contains(&column) {
                        StringMatchType::Equals
                    } else {
                        StringMatchType::StartsWith
                    }
                };

                let name = query.name.map(|name| {
                    CredentialFilterValue::Name(StringMatch {
                        r#match: get_string_match_type(
                            CredentialListQueryExactColumnBindingEnum::Name,
                        ),
                        value: name,
                    })
                });

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

                let states = query.status.map(|values| {
                    CredentialFilterValue::State(
                        values.into_iter().map(|status| status.into()).collect(),
                    )
                });

                ListFilterCondition::default() & name & role & ids & states
            };

            Ok(core
                .credential_service
                .get_credential_list(GetCredentialQueryFiltersDTO {
                    query: GetCredentialQueryDTO {
                        pagination: Some(ListPagination {
                            page: query.page,
                            page_size: query.page_size,
                        }),
                        sorting: query.sort.map(|column| ListSorting {
                            column: column.into(),
                            direction: convert_inner(query.sort_direction),
                        }),
                        filtering: Some(condition),
                        include: query.include.map(convert_inner),
                    },
                    organisation_id: Some(into_id(&query.organisation_id)?),
                })
                .await?
                .into())
        })
    }
}
