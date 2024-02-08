use one_core::model::{
    history::{HistoryFilterValue, HistorySearchEnum},
    list_filter::{ListFilterCondition, ListFilterValue},
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
        let created_date_from = value
            .created_date_from
            .map(HistoryFilterValue::CreatedDateFrom);
        let created_date_to = value.created_date_to.map(HistoryFilterValue::CreatedDateTo);
        let did_id = value.did_id.map(HistoryFilterValue::DidId);
        let credential_id = value.credential_id.map(HistoryFilterValue::CredentialId);
        let credential_schema_id = value
            .credential_schema_id
            .map(HistoryFilterValue::CredentialSchemaId);
        let search_query = value
            .search_text
            .map(|search_text| search_query_to_filter_value(search_text, value.search_type));
        let organisation_id =
            HistoryFilterValue::OrganisationId(value.organisation_id.into()).condition();

        organisation_id
            & entity_types
            & entity_id
            & action
            & created_date_from
            & created_date_to
            & did_id
            & credential_id
            & credential_schema_id
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
