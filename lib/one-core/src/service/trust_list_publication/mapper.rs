use super::dto::{
    ExactTrustListFilterColumn, GetTrustListPublicationResponseDTO, TrustEntryFilterParamsDTO,
    TrustListPublicationFilterParamsDTO, TrustListPublicationListItemResponseDTO,
};
use super::error::TrustListPublicationServiceError;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::trust_entry::TrustEntryFilterValue;
use crate::model::trust_list_publication::{TrustListPublication, TrustListPublicationFilterValue};

impl From<TrustListPublicationFilterParamsDTO>
    for ListFilterCondition<TrustListPublicationFilterValue>
{
    fn from(value: TrustListPublicationFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            TrustListPublicationFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            TrustListPublicationFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustListFilterColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(TrustListPublicationFilterValue::Ids);

        let types = value.types.map(TrustListPublicationFilterValue::Type);

        let roles = value.roles.map(TrustListPublicationFilterValue::Role);

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
            TrustListPublicationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & ids
            & types
            & roles
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}

impl From<TrustEntryFilterParamsDTO> for ListFilterCondition<TrustEntryFilterValue> {
    fn from(value: TrustEntryFilterParamsDTO) -> Self {
        let ids = value.ids.map(TrustEntryFilterValue::Ids);

        let identifier_ids = value
            .identifier_ids
            .map(TrustEntryFilterValue::IdentifierIds);

        let states = value.states.map(TrustEntryFilterValue::State);

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
            TrustEntryFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustEntryFilterValue>::from(ids)
            & identifier_ids
            & states
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}

impl GetTrustListPublicationResponseDTO {
    pub(super) async fn try_from(
        value: TrustListPublication,
    ) -> Result<Self, TrustListPublicationServiceError> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            deleted_at: value.deleted_at,
            name: value.name,
            identifier: value.identifier.as_ref().await?.to_owned().into(),
            r#type: value.r#type,
            role: value.role,
            content: Some(value.content),
            sequence_number: value.sequence_number,
            metadata: value.metadata,
            organisation_id: value.organisation.id(),
        })
    }
}

impl From<TrustListPublication> for TrustListPublicationListItemResponseDTO {
    fn from(value: TrustListPublication) -> Self {
        Self {
            id: value.id,
            name: value.name,
            created_date: value.created_date,
            last_modified: value.last_modified,
            organisation_id: value.organisation.id(),
            r#type: value.r#type,
            role: value.role,
            deleted_at: value.deleted_at,
        }
    }
}
