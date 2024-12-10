use one_core::model::history::{HistoryFilterValue, HistoryListQuery, HistorySearchEnum};
use one_core::model::list_filter::{ComparisonType, ListFilterCondition, ValueComparison};
use one_core::model::list_query::ListPagination;
use one_core::service::error::ServiceError;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::dto::{HistoryListBindingDTO, HistoryListQueryBindingDTO, HistorySearchBindingDTO};
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn get_history_list(
        &self,
        query: HistoryListQueryBindingDTO,
    ) -> Result<HistoryListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let organisation_id = into_id(&query.organisation_id)?;

            let mut conditions = vec![ListFilterCondition::Value(
                HistoryFilterValue::OrganisationId(organisation_id),
            )];

            if let Some(value) = query.entity_id {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityId(
                    into_id(&value)?,
                )));
            }
            if let Some(value) = query.entity_types {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityTypes(
                    value
                        .into_iter()
                        .map(|entity_type| entity_type.into())
                        .collect(),
                )));
            }
            if let Some(value) = query.action {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::Action(
                    value.into(),
                )));
            }
            if let Some(value) = query.did_id {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::DidId(
                    into_id(&value)?,
                )));
            }
            if let Some(value) = query.created_date_from {
                let created_date_from = deserialize_timestamp(&value)
                    .map_err(|e| ServiceError::ValidationError(e.to_string()))?;
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::CreatedDate(
                    ValueComparison {
                        comparison: ComparisonType::GreaterThanOrEqual,
                        value: created_date_from,
                    },
                )));
            }
            if let Some(value) = query.created_date_to {
                let created_date_to = deserialize_timestamp(&value)
                    .map_err(|e| ServiceError::ValidationError(e.to_string()))?;
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::CreatedDate(
                    ValueComparison {
                        comparison: ComparisonType::LessThanOrEqual,
                        value: created_date_to,
                    },
                )));
            }
            if let Some(value) = query.credential_id {
                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CredentialId(into_id(&value)?),
                ));
            }
            if let Some(value) = query.credential_schema_id {
                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CredentialSchemaId(into_id(&value)?),
                ));
            }

            if let Some(value) = query.search {
                conditions.push(ListFilterCondition::Value(search_query_to_filter_value(
                    value,
                )));
            }

            if let Some(proof_schema_id) = query.proof_schema_id {
                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::ProofSchemaId(into_id(&proof_schema_id)?),
                ));
            }

            Ok(core
                .history_service
                .get_history_list(HistoryListQuery {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    sorting: None,
                    filtering: Some(ListFilterCondition::And(conditions)),
                    include: None,
                })
                .await?
                .into())
        })
    }
}

fn deserialize_timestamp(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn search_query_to_filter_value(value: HistorySearchBindingDTO) -> HistoryFilterValue {
    match value.r#type {
        Some(search_type) => HistoryFilterValue::SearchQuery(value.text, search_type.into()),
        None => HistoryFilterValue::SearchQuery(value.text, HistorySearchEnum::All),
    }
}
