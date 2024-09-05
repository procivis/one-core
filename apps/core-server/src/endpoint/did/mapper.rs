use dto_mapper::convert_inner;
use one_core::model::did::DidFilterValue;
use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::service::did::dto::CreateDidRequestDTO;

use super::dto::{CreateDidRequestRestDTO, DidFilterQueryParamsRest, ExactDidFilterColumnRestEnum};

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

impl From<DidFilterQueryParamsRest> for ListFilterCondition<DidFilterValue> {
    fn from(value: DidFilterQueryParamsRest) -> Self {
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

        let key_algorithms = value.key_algorithms.map(|values| {
            DidFilterValue::KeyAlgorithms(
                values.into_iter().filter(|key| !key.is_empty()).collect(),
            )
        });

        let key_roles = value
            .key_roles
            .map(|values| DidFilterValue::KeyRoles(convert_inner(values)));

        let did_methods = value.did_methods.map(DidFilterValue::DidMethods);

        organisation_id
            & r#type
            & (name | did_value)
            & deactivated
            & key_algorithms
            & key_roles
            & did_methods
    }
}
