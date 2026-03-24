use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::trust_collection::TrustCollectionFilterValue;
use one_core::model::trust_list_subscription::TrustListSubscriptionFilterValue;
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner;

use crate::dto::common::ExactColumn;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::trust_collection::dto::{
    TrustCollectionFilterQueryParamsRestDTO, TrustListSubscriptionExactColumn,
    TrustListSubscriptionFilterQueryParamsRestDTO,
};

impl TryFrom<TrustCollectionFilterQueryParamsRestDTO>
    for ListFilterCondition<TrustCollectionFilterValue>
{
    type Error = ServiceError;
    fn try_from(value: TrustCollectionFilterQueryParamsRestDTO) -> Result<Self, Self::Error> {
        let organisation_id = TrustCollectionFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            TrustCollectionFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(TrustCollectionFilterValue::Ids);

        let created_date_after = value.created_date_after.map(|date| {
            TrustCollectionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustCollectionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustCollectionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustCollectionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}

impl From<TrustListSubscriptionFilterQueryParamsRestDTO>
    for ListFilterCondition<TrustListSubscriptionFilterValue>
{
    fn from(value: TrustListSubscriptionFilterQueryParamsRestDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let ids = value.ids.map(TrustListSubscriptionFilterValue::Ids);
        let name = value.name.map(|name| {
            TrustListSubscriptionFilterValue::Name(StringMatch {
                r#match: get_string_match_type(TrustListSubscriptionExactColumn::Name),
                value: name,
            })
        });
        let reference = value.reference.map(|reference| {
            TrustListSubscriptionFilterValue::Reference(StringMatch {
                r#match: get_string_match_type(TrustListSubscriptionExactColumn::Reference),
                value: reference,
            })
        });

        let roles = value
            .roles
            .map(convert_inner)
            .map(TrustListSubscriptionFilterValue::Role);
        let states = value
            .states
            .map(convert_inner)
            .map(TrustListSubscriptionFilterValue::State);
        let types = value.types.map(TrustListSubscriptionFilterValue::Type);

        let created_date_after = value.created_date_after.map(|date| {
            TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustListSubscriptionFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustListSubscriptionFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustListSubscriptionFilterValue>::default()
            & states
            & reference
            & roles
            & types
            & name
            & ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
