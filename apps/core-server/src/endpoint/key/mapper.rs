use one_core::model::key::KeyFilterValue;
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::service::error::ServiceError;

use super::dto::KeyFilterQueryParamsRest;
use crate::dto::common::ExactColumn;
use crate::dto::mapper::fallback_organisation_id_from_session;

impl TryFrom<KeyFilterQueryParamsRest> for ListFilterCondition<KeyFilterValue> {
    type Error = ServiceError;

    fn try_from(value: KeyFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = KeyFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let name = value.name.map(|name| {
            KeyFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let key_algorithms = value.key_types.map(KeyFilterValue::KeyTypes);
        let key_storages = value.key_storages.map(KeyFilterValue::KeyStorages);
        let ids = value.ids.map(KeyFilterValue::Ids);
        let remote = value.is_remote.map(KeyFilterValue::remote);

        let created_date_after = value.created_date_after.map(|date| {
            KeyFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            KeyFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            KeyFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            KeyFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & key_algorithms
            & key_storages
            & ids
            & remote
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}
