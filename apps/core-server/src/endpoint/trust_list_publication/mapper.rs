use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::trust_entry::TrustEntryFilterValue;
use one_core::model::trust_list_publication::TrustListPublicationFilterValue;
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner;

use crate::dto::common::ExactColumn;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::trust_list_publication::dto::{
    TrustEntryFilterQueryParamsRestDTO, TrustListPublicationFilterQueryParamsRestDTO,
};

impl TryFrom<TrustListPublicationFilterQueryParamsRestDTO>
    for ListFilterCondition<TrustListPublicationFilterValue>
{
    type Error = ServiceError;
    fn try_from(value: TrustListPublicationFilterQueryParamsRestDTO) -> Result<Self, Self::Error> {
        let organisation_id = TrustListPublicationFilterValue::OrganisationId(
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
            TrustListPublicationFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(TrustListPublicationFilterValue::Ids);

        let types = value
            .types
            .map(|types| TrustListPublicationFilterValue::Type(convert_inner(types)));

        let roles = value
            .roles
            .map(|roles| TrustListPublicationFilterValue::Role(convert_inner(roles)));

        let created_date_after = value.created_date_after.map(|date| {
            TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustListPublicationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & ids
            & types
            & roles
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}

impl TryFrom<TrustEntryFilterQueryParamsRestDTO> for ListFilterCondition<TrustEntryFilterValue> {
    type Error = ServiceError;
    fn try_from(value: TrustEntryFilterQueryParamsRestDTO) -> Result<Self, Self::Error> {
        let ids = value.ids.map(TrustEntryFilterValue::Ids);

        let identifier_ids = value
            .identifier_ids
            .map(TrustEntryFilterValue::IdentifierIds);

        let statuses = value
            .states
            .map(|states| TrustEntryFilterValue::Status(convert_inner(states)));

        let created_date_after = value.created_date_after.map(|date| {
            TrustEntryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustEntryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustEntryFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustEntryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(ListFilterCondition::<TrustEntryFilterValue>::from(ids)
            & identifier_ids
            & statuses
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}
