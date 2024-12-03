use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::model::trust_entity::TrustEntityState;
use one_core::service::trust_entity::dto::{CreateTrustEntityRequestDTO, TrustEntityFilterValue};

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

        ListFilterCondition::<TrustEntityFilterValue>::from(did_id)
            & trust_anchor_id
            & name
            & role
            & organisation_id
    }
}

impl From<CreateTrustEntityRequestRestDTO> for CreateTrustEntityRequestDTO {
    fn from(value: CreateTrustEntityRequestRestDTO) -> Self {
        Self {
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role.into(),
            state: TrustEntityState::Active,
            trust_anchor_id: value.trust_anchor_id,
            did_id: value.did_id,
        }
    }
}
