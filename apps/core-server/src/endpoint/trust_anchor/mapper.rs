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

        let is_publisher = value.is_publisher.map(TrustAnchorFilterValue::is_publisher);

        let r#type = value.r#type.map(|r#type| {
            TrustAnchorFilterValue::Type(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumnRestEnum::Type),
                value: r#type,
            })
        });

        ListFilterCondition::<TrustAnchorFilterValue>::from(name) & is_publisher & r#type
    }
}
