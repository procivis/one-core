use one_core::{
    model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch, StringMatchType},
    service::{credential::dto::CredentialFilterValue, error::ServiceError},
};

use crate::dto::common::ExactColumn;

use super::dto::CredentialsFilterQueryParamsRest;

impl TryFrom<CredentialsFilterQueryParamsRest> for ListFilterCondition<CredentialFilterValue> {
    type Error = ServiceError;

    fn try_from(value: CredentialsFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            CredentialFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let role = value
            .role
            .map(|role| CredentialFilterValue::Role(role.into()));

        Ok(organisation_id & name & role)
    }
}
