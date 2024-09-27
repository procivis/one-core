use one_core::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use one_core::service::proof::dto::ProofFilterValue;
use one_dto_mapper::convert_inner;

use super::dto::ProofsFilterQueryParamsRest;
use crate::dto::common::ExactColumn;

impl From<ProofsFilterQueryParamsRest> for ListFilterCondition<ProofFilterValue> {
    fn from(value: ProofsFilterQueryParamsRest) -> Self {
        let exact = value.exact.unwrap_or_default();

        let organisation_id = ProofFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            let filter = if exact.contains(&ExactColumn::Name) {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            ProofFilterValue::Name(filter)
        });

        let proof_states = value
            .proof_states
            .map(|proof_states| ProofFilterValue::ProofStates(convert_inner(proof_states)));

        let proof_ids = value.ids.map(ProofFilterValue::ProofIds);
        let proof_schema_ids = value.proof_schema_ids.map(ProofFilterValue::ProofSchemaIds);

        organisation_id & name & proof_states & proof_schema_ids & proof_ids
    }
}
