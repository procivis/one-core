use one_core::model::list_filter::{
    ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
};
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;

use super::dto::{CredentialSchemasExactColumn, CredentialSchemasFilterQueryParamsRest};

impl From<CredentialSchemasFilterQueryParamsRest>
    for ListFilterCondition<CredentialSchemaFilterValue>
{
    fn from(value: CredentialSchemasFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            CredentialSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name: Self = value
            .name
            .map(|name| {
                CredentialSchemaFilterValue::Name(StringMatch {
                    r#match: get_string_match_type(CredentialSchemasExactColumn::Name),
                    value: name,
                })
            })
            .into();

        let format = value.format.map(|format| {
            CredentialSchemaFilterValue::Format(StringMatch {
                r#match: get_string_match_type(CredentialSchemasExactColumn::Format),
                value: format,
            })
        });

        let schema_id = value.schema_id.map(|schema_id| {
            CredentialSchemaFilterValue::SchemaId(StringMatch {
                r#match: get_string_match_type(CredentialSchemasExactColumn::SchemaId),
                value: schema_id,
            })
        });

        let credential_schema_ids = value
            .ids
            .map(CredentialSchemaFilterValue::CredentialSchemaIds);

        organisation_id & (name | format) & schema_id & credential_schema_ids
    }
}
