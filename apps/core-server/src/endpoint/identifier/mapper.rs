use one_core::model::identifier::IdentifierFilterValue;
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_dto_mapper::convert_inner;

use super::dto::{ExactIdentifierFilterColumnRestEnum, IdentifierFilterQueryParamsRestDTO};

impl From<IdentifierFilterQueryParamsRestDTO> for ListFilterCondition<IdentifierFilterValue> {
    fn from(value: IdentifierFilterQueryParamsRestDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            IdentifierFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            IdentifierFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactIdentifierFilterColumnRestEnum::Name),
                value: name,
            })
        });

        let ids = value.ids.map(IdentifierFilterValue::Ids);
        let types = value
            .types
            .map(|types| IdentifierFilterValue::Types(convert_inner(types)));
        let state = value
            .state
            .map(|state| IdentifierFilterValue::State(state.into()));
        let did_methods = value.did_methods.map(IdentifierFilterValue::DidMethods);
        let is_remote = value
            .is_remote
            .map(|is_remote| IdentifierFilterValue::IsRemote(is_remote.into()));
        let key_algorithms = value
            .key_algorithms
            .map(IdentifierFilterValue::KeyAlgorithms);
        let key_roles = value
            .key_roles
            .map(|key_roles| IdentifierFilterValue::KeyRoles(convert_inner(key_roles)));
        let key_storages = value.key_storages.map(IdentifierFilterValue::KeyStorages);

        organisation_id
            & name
            & ids
            & types
            & state
            & did_methods
            & is_remote
            & key_algorithms
            & key_roles
            & key_storages
    }
}
