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
        let r#type = value
            .r#type
            .map(|r#type| IdentifierFilterValue::Type(r#type.into()));
        let status = value
            .state
            .map(|status| IdentifierFilterValue::Status(status.into()));
        let key_algorithms = value
            .key_algorithms
            .map(IdentifierFilterValue::KeyAlgorithms);
        let key_roles = value
            .key_roles
            .map(|key_roles| IdentifierFilterValue::KeyRoles(convert_inner(key_roles)));
        let key_storages = value.key_storages.map(IdentifierFilterValue::KeyStorages);

        organisation_id & name & ids & r#type & status & key_algorithms & key_roles & key_storages
    }
}
