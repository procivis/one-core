use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, ValueComparison,
};
use one_core::service::proof_schema::dto::ProofSchemaFilterValue;

use super::dto::ProofSchemasFilterQueryParamsRest;
use crate::dto::common::ExactColumn;

impl From<ProofSchemasFilterQueryParamsRest> for ListFilterCondition<ProofSchemaFilterValue> {
    fn from(value: ProofSchemasFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();

        let organisation_id =
            ProofSchemaFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            let filter = if exact.contains(&ExactColumn::Name) {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            ProofSchemaFilterValue::Name(filter)
        });

        let proof_schema_ids = value.ids.map(ProofSchemaFilterValue::ProofSchemaIds);

        let formats = value.formats.map(ProofSchemaFilterValue::Formats);

        let created_date_after = value.created_date_after.map(|date| {
            ProofSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            ProofSchemaFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            ProofSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            ProofSchemaFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & proof_schema_ids
            & formats
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
