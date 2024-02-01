use one_core::model::{
    history::HistoryFilterValue,
    list_filter::{ListFilterCondition, ListFilterValue},
};
use one_core::service::error::{BusinessLogicError, ServiceError};

use crate::endpoint::history::dto::HistoryFilterQueryParamsRest;

impl TryFrom<HistoryFilterQueryParamsRest> for ListFilterCondition<HistoryFilterValue> {
    type Error = ServiceError;

    fn try_from(value: HistoryFilterQueryParamsRest) -> Result<Self, Self::Error> {
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

        let has_specified_only_one_of_search_params =
            value.search_type.is_some() ^ value.search_text.is_some();
        if has_specified_only_one_of_search_params {
            return Err(ServiceError::BusinessLogic(
                BusinessLogicError::GeneralInputValidationError,
            ));
        }

        let search_query = if let Some(search_text) = value.search_text {
            value
                .search_type
                .map(|search_type| HistoryFilterValue::SearchQuery(search_text, search_type.into()))
        } else {
            None
        };

        let organisation_id =
            HistoryFilterValue::OrganisationId(value.organisation_id.into()).condition();

        Ok(organisation_id
            & entity_type
            & entity_id
            & action
            & created_date_from
            & created_date_to
            & did_id
            & credential_id
            & credential_schema_id
            & search_query)
    }
}
