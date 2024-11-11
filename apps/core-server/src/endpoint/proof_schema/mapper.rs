use one_core::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
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

        organisation_id & name & proof_schema_ids
    }
}
