use one_core::model::identifier::IdentifierFilterValue;
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};

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

        let r#type = value
            .r#type
            .map(|r#type| IdentifierFilterValue::Type(r#type.into()));
        let status = value
            .status
            .map(|status| IdentifierFilterValue::Status(status.into()));

        organisation_id & name & r#type & status
    }
}
