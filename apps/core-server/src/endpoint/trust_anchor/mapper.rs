use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
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

        let created_date_after = value.created_date_after.map(|date| {
            TrustAnchorFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustAnchorFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustAnchorFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustAnchorFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustAnchorFilterValue>::from(name)
            & is_publisher
            & r#type
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
