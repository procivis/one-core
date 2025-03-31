use std::sync::Arc;

use one_core::model::history::{
    GetHistoryList, History, HistoryAction, HistoryEntityType, HistoryFilterValue,
    HistoryListQuery, HistoryMetadata,
};
use one_core::model::list_filter::ListFilterCondition;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::Organisation;
use one_core::repository::history_repository::HistoryRepository;
use shared_types::{EntityId, HistoryId};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct TestingHistoryParams {
    pub id: Option<HistoryId>,
    pub created_date: Option<OffsetDateTime>,
    pub action: Option<HistoryAction>,
    pub entity_id: Option<EntityId>,
    pub entity_type: Option<HistoryEntityType>,
    pub metadata: Option<HistoryMetadata>,
    pub name: Option<String>,
    pub target: Option<String>,
}

pub struct HistoriesDB {
    repository: Arc<dyn HistoryRepository>,
}

impl HistoriesDB {
    pub fn new(repository: Arc<dyn HistoryRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        organisation: &Organisation,
        params: TestingHistoryParams,
    ) -> History {
        let now = OffsetDateTime::now_utc();

        let history_id = params.id.unwrap_or(HistoryId::from(Uuid::new_v4()));
        let history = History {
            id: history_id.to_owned(),
            created_date: params.created_date.unwrap_or(now),
            action: params.action.unwrap_or(HistoryAction::Accepted),
            entity_id: Some(params.entity_id.unwrap_or(Uuid::new_v4().into())),
            entity_type: params.entity_type.unwrap_or(HistoryEntityType::Credential),
            metadata: params.metadata,
            organisation_id: organisation.id,
            name: params.name.unwrap_or_default(),
            target: params.target,
        };

        self.repository
            .create_history(history.clone())
            .await
            .unwrap();

        history
    }

    pub async fn get_by_entity_id(&self, entity_id: &EntityId) -> GetHistoryList {
        let query = HistoryListQuery {
            pagination: Some(ListPagination {
                page: 0,
                page_size: 10,
            }),
            sorting: None,
            filtering: Some(ListFilterCondition::Value(HistoryFilterValue::EntityId(
                *entity_id,
            ))),

            include: None,
        };

        self.repository.get_history_list(query).await.unwrap()
    }
}
