use super::dto::{CreateDidRequestRestDTO, DidFilterQueryParamsRest, ExactDidFilterColumnRestEnum};
use one_core::model::{
    did::DidFilterValue,
    list_filter::{ListFilterCondition, ListFilterValue, StringMatch, StringMatchType},
};
use one_core::service::{did::dto::CreateDidRequestDTO, error::ServiceError};

impl From<CreateDidRequestRestDTO> for CreateDidRequestDTO {
    fn from(value: CreateDidRequestRestDTO) -> Self {
        Self {
            name: value.name,
            organisation_id: value.organisation_id,
            did_method: value.method,
            did_type: one_core::model::did::DidType::Local,
            keys: value.keys.into(),
            params: value.params,
        }
    }
}

impl TryFrom<DidFilterQueryParamsRest> for ListFilterCondition<DidFilterValue> {
    type Error = ServiceError;

    fn try_from(value: DidFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = DidFilterValue::OrganisationId(value.organisation_id).condition();

        let r#type = value
            .r#type
            .map(|r#type| DidFilterValue::Type(r#type.into()));

        let name: Self = value
            .name
            .map(|name| {
                DidFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(ExactDidFilterColumnRestEnum::Name),
                    value: name,
                })
            })
            .into();

        let did_value = value.did.map(|did| {
            DidFilterValue::Did(StringMatch {
                r#match: get_string_match_type(ExactDidFilterColumnRestEnum::Did),
                value: did,
            })
        });

        let deactivated = value.deactivated.map(DidFilterValue::deactivated);

        Ok(organisation_id & r#type & (name | did_value) & deactivated)
    }
}
