use one_core::model::list_filter::{ListFilterCondition, StringMatch, StringMatchType};
use one_core::service::credential::dto::{CredentialFilterValue, GetCredentialQueryFiltersDTO};

use super::dto::{CredentialsFilterQueryParamsRest, GetCredentialQuery};
use crate::dto::common::ExactColumn;

impl From<CredentialsFilterQueryParamsRest> for ListFilterCondition<CredentialFilterValue> {
    fn from(value: CredentialsFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = value.name.map(|name| {
            CredentialFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let role = value
            .role
            .map(|role| CredentialFilterValue::Role(role.into()));

        let credential_ids = value.ids.map(CredentialFilterValue::CredentialIds);

        let states = value.status.map(|values| {
            CredentialFilterValue::State(values.into_iter().map(|status| status.into()).collect())
        });

        ListFilterCondition::default() & name & role & credential_ids & states
    }
}

impl From<GetCredentialQuery> for GetCredentialQueryFiltersDTO {
    fn from(value: GetCredentialQuery) -> Self {
        let organisation_id = value.filter.organisation_id;
        GetCredentialQueryFiltersDTO {
            query: value.into(),
            organisation_id: Some(organisation_id),
        }
    }
}
