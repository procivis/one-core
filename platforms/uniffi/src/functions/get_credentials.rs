use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential::dto::{CredentialFilterValue, GetCredentialQueryDTO};
use one_core::service::error::{BusinessLogicError, ServiceError};
use one_dto_mapper::convert_inner;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::{
    CredentialListBindingDTO, CredentialListQueryBindingDTO,
    CredentialListQueryExactColumnBindingEnum, OneCoreBinding, SearchTypeBindingEnum,
};

impl OneCoreBinding {
    pub fn get_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let condition = {
                if query.name.is_some()
                    && query.search_type.is_some()
                    && query.search_text.is_some()
                {
                    return Err(ServiceError::BusinessLogic(
                        BusinessLogicError::GeneralInputValidationError,
                    )
                    .into());
                }

                let exact = query.exact.unwrap_or_default();
                let get_string_match_type = |column| {
                    if exact.contains(&column) {
                        StringMatchType::Equals
                    } else {
                        StringMatchType::StartsWith
                    }
                };

                let organisation =
                    CredentialFilterValue::OrganisationId(into_id(&query.organisation_id)?)
                        .condition();

                let name = query.name.map(|name| {
                    CredentialFilterValue::CredentialSchemaName(StringMatch {
                        r#match: get_string_match_type(
                            CredentialListQueryExactColumnBindingEnum::Name,
                        ),
                        value: name,
                    })
                });

                let search_filters = match (query.search_text, query.search_type) {
                    (Some(search_test), Some(search_type)) => {
                        organisation
                            & ListFilterCondition::Or(
                                search_type
                                    .into_iter()
                                    .map(|filter| {
                                        match filter {
                                            SearchTypeBindingEnum::ClaimName => {
                                                CredentialFilterValue::ClaimName(StringMatch {
                                                    r#match: StringMatchType::Contains,
                                                    value: search_test.clone(),
                                                })
                                            }
                                            SearchTypeBindingEnum::ClaimValue => {
                                                CredentialFilterValue::ClaimValue(StringMatch {
                                                    r#match: StringMatchType::Contains,
                                                    value: search_test.clone(),
                                                })
                                            }
                                            SearchTypeBindingEnum::CredentialSchemaName => {
                                                CredentialFilterValue::CredentialSchemaName(
                                                    StringMatch {
                                                        r#match: StringMatchType::Contains,
                                                        value: search_test.clone(),
                                                    },
                                                )
                                            }
                                        }
                                        .condition()
                                    })
                                    .collect(),
                            )
                    }
                    _ => organisation,
                };

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

                search_filters & name & role & ids & states
            };

            Ok(core
                .credential_service
                .get_credential_list(GetCredentialQueryDTO {
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
                })
                .await?
                .into())
        })
    }
}
