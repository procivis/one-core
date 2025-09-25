use one_core::model::history::{HistoryFilterValue, HistorySearchEnum};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, ValueComparison,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::convert_inner;

use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::history::dto::{HistoryFilterQueryParamsRest, HistorySearchEnumRest};

impl TryFrom<HistoryFilterQueryParamsRest> for ListFilterCondition<HistoryFilterValue> {
    type Error = ServiceError;
    fn try_from(value: HistoryFilterQueryParamsRest) -> Result<Self, Self::Error> {
        let entity_types = value.entity_types.map(|values| {
            HistoryFilterValue::EntityTypes(
                values
                    .into_iter()
                    .map(|entity_type| entity_type.into())
                    .collect(),
            )
        });
        let entity_id = value.entity_id.map(HistoryFilterValue::EntityId);
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
        let organisation_id = HistoryFilterValue::OrganisationId(
            fallback_organisation_id_from_session(value.organisation_id)?,
        )
        .condition();

        let proof_schema_id = value.proof_schema_id.map(HistoryFilterValue::ProofSchemaId);

        let user = value.user.map(HistoryFilterValue::User);

        Ok(organisation_id
            & entity_types
            & entity_id
            & actions
            & created_date_after
            & created_date_before
            & identifier_id
            & credential_id
            & credential_schema_id
            & proof_schema_id
            & search_query
            & user)
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
