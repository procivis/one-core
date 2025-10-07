use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
use one_core::service::error::ServiceError;
use one_core::service::trust_entity::dto::{CreateTrustEntityRequestDTO, TrustEntityFilterValue};
use one_dto_mapper::{convert_inner, try_convert_inner};

use super::dto::{CreateTrustEntityRequestRestDTO, TrustEntityFilterQueryParamsRestDto};

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

        let did_id = value.did_id.map(TrustEntityFilterValue::DidId);

        let organisation_id = value
            .organisation_id
            .map(TrustEntityFilterValue::OrganisationId);

        let types = value
            .types
            .map(convert_inner)
            .map(TrustEntityFilterValue::Types);

        let states = value
            .states
            .map(convert_inner)
            .map(TrustEntityFilterValue::States);

        let entity_key = value.entity_key.map(TrustEntityFilterValue::EntityKey);

        let created_date_after = value.created_date_after.map(|date| {
            TrustEntityFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustEntityFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            TrustEntityFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustEntityFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustEntityFilterValue>::from(did_id)
            & trust_anchor_id
            & name
            & role
            & organisation_id
            & types
            & states
            & entity_key
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}

impl TryFrom<CreateTrustEntityRequestRestDTO> for CreateTrustEntityRequestDTO {
    type Error = ServiceError;

    fn try_from(value: CreateTrustEntityRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            logo: try_convert_inner(value.logo)?,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role.into(),
            trust_anchor_id: value.trust_anchor_id,
            did_id: value.did_id,
            identifier_id: value.identifier_id,
            r#type: value.r#type.map(Into::into),
            content: value
                .content
                .map(|s| String::from_utf8_lossy(s.as_bytes()).to_string()),
            organisation_id: value.organisation_id,
        })
    }
}
