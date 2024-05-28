use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::service::trust_entity::dto::TrustEntityFilterValue;

use super::dto::TrustEntityFilterQueryParamsRestDto;

impl From<TrustEntityFilterQueryParamsRestDto> for ListFilterCondition<TrustEntityFilterValue> {
    fn from(value: TrustEntityFilterQueryParamsRestDto) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustEntityFilterValue::Name(StringMatch {
                r#match: get_string_match_type(crate::dto::common::ExactColumn::Name),
                value: name,
            })
        });

        let role = value
            .role
            .map(|role| TrustEntityFilterValue::Role(role.into()));

        let trust_anchor_id = value
            .trust_anchor_id
            .map(TrustEntityFilterValue::TrustAnchor);

        let organisation = TrustEntityFilterValue::Organisation(value.organisation_id).condition();

        organisation & trust_anchor_id & name & role
    }
}
