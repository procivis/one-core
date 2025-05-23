use one_core::model::history::{HistoryFilterValue, HistorySearchEnum};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};

use crate::endpoint::history::dto::{HistoryFilterQueryParamsRest, HistorySearchEnumRest};

impl From<HistoryFilterQueryParamsRest> for ListFilterCondition<HistoryFilterValue> {
    fn from(value: HistoryFilterQueryParamsRest) -> Self {
        let entity_types = value.entity_types.map(|values| {
            HistoryFilterValue::EntityTypes(
                values
                    .into_iter()
                    .map(|entity_type| entity_type.into())
                    .collect(),
            )
        });
        let entity_id = value.entity_id.map(HistoryFilterValue::EntityId);
        let action = value
            .action
            .map(|value| HistoryFilterValue::Action(value.into()));
        let created_date_from = value.created_date_from.map(|date| {
            HistoryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_to = value.created_date_to.map(|date| {
            HistoryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });
        let identifier_id = value.identifier_id.map(HistoryFilterValue::IdentifierId);
        let credential_id = value.credential_id.map(HistoryFilterValue::CredentialId);
        let credential_schema_id = value
            .credential_schema_id
            .map(HistoryFilterValue::CredentialSchemaId);
        let search_query = value
            .search_text
            .map(|search_text| search_query_to_filter_value(search_text, value.search_type));
        let organisation_id = HistoryFilterValue::OrganisationId(value.organisation_id).condition();

        let proof_schema_id = value.proof_schema_id.map(HistoryFilterValue::ProofSchemaId);

        organisation_id
            & entity_types
            & entity_id
            & action
            & created_date_from
            & created_date_to
            & identifier_id
            & credential_id
            & credential_schema_id
            & proof_schema_id
            & search_query
    }
}

fn search_query_to_filter_value(
    search_text: String,
    search_type: Option<HistorySearchEnumRest>,
) -> HistoryFilterValue {
    if let Some(value) = search_type {
        HistoryFilterValue::SearchQuery(search_text, value.into())
    } else {
        HistoryFilterValue::SearchQuery(search_text, HistorySearchEnum::All)
    }
}
