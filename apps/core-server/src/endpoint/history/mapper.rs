use one_core::model::history::{HistoryFilterValue, HistorySearchEnum};
use one_core::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use one_dto_mapper::convert_inner;

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
        let entity_ids = value.entity_ids.map(HistoryFilterValue::EntityIds);
        let actions = value
            .actions
            .map(|values| HistoryFilterValue::Actions(convert_inner(values)));
        let created_date_after = value.created_date_after.map(|date| {
            HistoryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
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
        let organisation_ids = value
            .organisation_ids
            .map(HistoryFilterValue::OrganisationIds);

        let proof_schema_id = value.proof_schema_id.map(HistoryFilterValue::ProofSchemaId);

        let users = value.users.map(HistoryFilterValue::Users);
        let sources = value
            .sources
            .map(|values| HistoryFilterValue::Sources(convert_inner(values)));

        Self::default()
            & organisation_ids
            & entity_types
            & entity_ids
            & actions
            & created_date_after
            & created_date_before
            & identifier_id
            & credential_id
            & credential_schema_id
            & proof_schema_id
            & search_query
            & users
            & sources
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
