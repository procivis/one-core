use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use one_core::model::{
    history::{HistoryFilterValue, HistoryListQuery},
    list_filter::ListFilterCondition,
    list_query::ListPagination,
};

use crate::{
    dto::{HistoryListBindingDTO, HistoryListQueryBindingDTO},
    error::BindingError,
    utils::into_uuid,
    OneCoreBinding,
};

impl OneCoreBinding {
    pub fn get_history_list(
        &self,
        query: HistoryListQueryBindingDTO,
    ) -> Result<HistoryListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;

            let organisation_id = into_uuid(&query.organisation_id)?;

            let mut conditions = vec![ListFilterCondition::Value(
                HistoryFilterValue::OrganisationId(organisation_id),
            )];

            if let Some(value) = query.entity_id {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityId(
                    into_uuid(&value)?.into(),
                )));
            }
            if let Some(value) = query.entity_type {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::EntityType(
                    value.into(),
                )));
            }
            if let Some(value) = query.action {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::Action(
                    value.into(),
                )));
            }
            if let Some(value) = query.did_id {
                conditions.push(ListFilterCondition::Value(HistoryFilterValue::DidId(
                    into_uuid(&value)?.into(),
                )));
            }
            if let Some(value) = query.created_date_from {
                let created_date_from = deserialize_timestamp(&value)?;

                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CreatedDateFrom(created_date_from),
                ));
            }
            if let Some(value) = query.created_date_to {
                let created_date_to = deserialize_timestamp(&value)?;

                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CreatedDateTo(created_date_to),
                ));
            }
            if let Some(value) = query.credential_id {
                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CredentialId(into_uuid(&value)?),
                ));
            }
            if let Some(value) = query.credential_schema_id {
                conditions.push(ListFilterCondition::Value(
                    HistoryFilterValue::CredentialSchemaId(into_uuid(&value)?),
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
                })
                .await?
                .into())
        })
    }
}

fn deserialize_timestamp(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}