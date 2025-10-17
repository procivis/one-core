use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
use one_core::model::organisation::OrganisationFilterValue;
use one_core::service::error::ServiceError;
use one_core::service::organisation::dto::UpsertOrganisationRequestDTO;
use shared_types::OrganisationId;

use super::dto::{
    CreateOrganisationResponseRestDTO, OrganisationFilterQueryParamsRest,
    UpsertOrganisationRequestRestDTO,
};
use crate::dto::common::ExactColumn;

impl From<OrganisationId> for CreateOrganisationResponseRestDTO {
    fn from(value: OrganisationId) -> Self {
        Self { id: value }
    }
}

pub(crate) fn upsert_request_from_request(
    id: OrganisationId,
    request: UpsertOrganisationRequestRestDTO,
) -> UpsertOrganisationRequestDTO {
    UpsertOrganisationRequestDTO {
        id,
        name: request.name,
        deactivate: request.deactivate,
        wallet_provider: request.wallet_provider,
        wallet_provider_issuer: request.wallet_provider_issuer,
    }
}

impl TryFrom<OrganisationFilterQueryParamsRest> for ListFilterCondition<OrganisationFilterValue> {
    type Error = ServiceError;

    fn try_from(value: OrganisationFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            OrganisationFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let created_date_after = value.created_date_after.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            OrganisationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            OrganisationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(ListFilterCondition::<OrganisationFilterValue>::default()
            & name
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}
