use one_core::model::{
    history::HistoryFilterValue,
    list_filter::{ListFilterCondition, ListFilterValue},
};

use crate::endpoint::history::dto::HistoryFilterQueryParamsRest;

impl From<HistoryFilterQueryParamsRest> for ListFilterCondition<HistoryFilterValue> {
    fn from(value: HistoryFilterQueryParamsRest) -> Self {
        let entity_type = value
            .entity_type
            .map(|value| HistoryFilterValue::EntityType(value.into()));
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
        let organisation_id =
            HistoryFilterValue::OrganisationId(value.organisation_id.into()).condition();

        organisation_id
            & entity_type
            & entity_id
            & action
            & created_date_from
            & created_date_to
            & did_id
            & credential_id
            & credential_schema_id
    }
}
