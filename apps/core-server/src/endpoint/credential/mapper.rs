use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::service::credential::dto::CredentialFilterValue;
use one_core::service::error::{BusinessLogicError, ServiceError};

use super::dto::{CredentialsFilterQueryParamsRest, SearchType};
use crate::dto::common::ExactColumn;

impl TryFrom<CredentialsFilterQueryParamsRest> for ListFilterCondition<CredentialFilterValue> {
    type Error = ServiceError;

    fn try_from(value: CredentialsFilterQueryParamsRest) -> Result<Self, Self::Error> {
        if value.name.is_some() && value.search_type.is_some() && value.search_text.is_some() {
            return Err(BusinessLogicError::GeneralInputValidationError.into());
        }

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
            CredentialFilterValue::CredentialSchemaName(StringMatch {
                r#match: get_string_match_type(ExactColumn::Name),
                value: name,
            })
        });

        let profile = value.profile.map(|profile| {
            CredentialFilterValue::Profile(StringMatch {
                r#match: StringMatchType::Equals,
                value: profile,
            })
        });

        let search_filters = match (value.search_text, value.search_type) {
            (Some(search_test), Some(search_type)) => {
                organisation_id
                    & ListFilterCondition::Or(
                        search_type
                            .into_iter()
                            .map(|filter| {
                                match filter {
                                    SearchType::ClaimName => {
                                        CredentialFilterValue::ClaimName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                    SearchType::ClaimValue => {
                                        CredentialFilterValue::ClaimValue(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                    SearchType::CredentialSchemaName => {
                                        CredentialFilterValue::CredentialSchemaName(StringMatch {
                                            r#match: StringMatchType::Contains,
                                            value: search_test.clone(),
                                        })
                                    }
                                }
                                .condition()
                            })
                            .collect(),
                    )
            }
            _ => organisation_id,
        };

        let role = value
            .role
            .map(|role| CredentialFilterValue::Role(role.into()));

        let credential_ids = value.ids.map(CredentialFilterValue::CredentialIds);

        let states = value.status.map(|values| {
            CredentialFilterValue::State(values.into_iter().map(|status| status.into()).collect())
        });

        Ok(search_filters & name & role & credential_ids & states & profile)
    }
}
