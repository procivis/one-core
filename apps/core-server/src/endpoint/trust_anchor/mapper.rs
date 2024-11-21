use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::service::trust_anchor::dto::TrustAnchorFilterValue;

use super::dto::{ExactTrustAnchorFilterColumnRestEnum, TrustAnchorsFilterQueryParamsRest};

impl From<TrustAnchorsFilterQueryParamsRest> for ListFilterCondition<TrustAnchorFilterValue> {
    fn from(value: TrustAnchorsFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustAnchorFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnRestEnum::Name),
                value: name,
            })
        });

        let role = value
            .role
            .map(|role| TrustAnchorFilterValue::Role(role.into()));

        let type_ = value.r#type.map(|type_| {
            TrustAnchorFilterValue::Type(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnRestEnum::Type),
                value: type_,
            })
        });

        ListFilterCondition::<TrustAnchorFilterValue>::from(name) & role & type_
    }
}
