use crate::{
    error::BindingError, utils::into_id, DidListBindingDTO, DidListQueryBindingDTO,
    ExactDidFilterColumnBindingEnum, OneCoreBinding,
};
use dto_mapper::convert_inner;
use one_core::model::{
    did::{DidFilterValue, DidListQuery},
    list_filter::{ListFilterValue, StringMatch, StringMatchType},
    list_query::{ListPagination, ListSorting},
};

impl OneCoreBinding {
    pub fn get_dids(
        &self,
        query: DidListQueryBindingDTO,
    ) -> Result<DidListBindingDTO, BindingError> {
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

                let organisation =
                    DidFilterValue::OrganisationId(into_id(&query.organisation_id)?).condition();

                let name = query.name.map(|name| {
                    DidFilterValue::Name(StringMatch {
                        r#match: get_string_match_type(ExactDidFilterColumnBindingEnum::Name),
                        value: name,
                    })
                });

                let did_value = query.did.map(|did| {
                    DidFilterValue::Name(StringMatch {
                        r#match: get_string_match_type(ExactDidFilterColumnBindingEnum::Did),
                        value: did,
                    })
                });

                let r#type = query
                    .r#type
                    .map(|r#type| DidFilterValue::Type(r#type.into()));

                let deactivated = query.deactivated.map(DidFilterValue::Deactivated);

                let key_algorithms = query.key_algorithms.map(DidFilterValue::KeyAlgorithms);

                let key_roles = query.key_roles.map(|values| {
                    DidFilterValue::KeyRoles(values.into_iter().map(|role| role.into()).collect())
                });

                organisation & name & did_value & r#type & deactivated & key_algorithms & key_roles
            };

            Ok(core
                .did_service
                .get_did_list(DidListQuery {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    sorting: query.sort.map(|column| ListSorting {
                        column: column.into(),
                        direction: convert_inner(query.sort_direction),
                    }),
                    filtering: Some(condition),
                    include: None,
                })
                .await?
                .into())
        })
    }
}
