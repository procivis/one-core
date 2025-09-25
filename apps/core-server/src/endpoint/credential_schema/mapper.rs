use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::service::credential_schema::dto::CredentialSchemaFilterValue;
use one_core::service::error::ServiceError;

use super::dto::{CredentialSchemasExactColumn, CredentialSchemasFilterQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;

impl TryFrom<CredentialSchemasFilterQueryParamsRest>
    for ListFilterCondition<CredentialSchemaFilterValue>
{
    type Error = ServiceError;

    fn try_from(value: CredentialSchemasFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id = CredentialSchemaFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let name = value.name.map(|name| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(CredentialSchemasExactColumn::Name),
                value: name,
            })
        });

        let formats = value.formats.map(CredentialSchemaFilterValue::Formats);

        let schema_id = value.schema_id.map(|schema_id| {
            CredentialSchemaFilterValue::SchemaId(StringMatch {
                r#match: get_string_match_type(CredentialSchemasExactColumn::SchemaId),
                value: schema_id,
            })
        });

        let credential_schema_ids = value
            .ids
            .map(CredentialSchemaFilterValue::CredentialSchemaIds);

        let created_date_after = value.created_date_after.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            CredentialSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        Ok(organisation_id
            & name
            & formats
            & schema_id
            & credential_schema_ids
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before)
    }
}
