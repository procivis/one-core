use std::sync::Arc;

use shared_types::{EntityId, HistoryId};
use time::OffsetDateTime;
use uuid::Uuid;

use one_core::{
    model::{
        history::{History, HistoryAction, HistoryEntityType},
        organisation::Organisation,
    },
    repository::history_repository::HistoryRepository,
};

#[derive(Debug, Default)]
pub struct TestingHistoryParams {
    pub id: Option<HistoryId>,
    pub created_date: Option<OffsetDateTime>,
    pub action: Option<HistoryAction>,
    pub entity_id: Option<EntityId>,
    pub entity_type: Option<HistoryEntityType>,
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
            entity_id: params.entity_id.unwrap_or(Uuid::new_v4().into()),
            entity_type: params.entity_type.unwrap_or(HistoryEntityType::Credential),
            organisation: Some(organisation.clone()),
        };

        self.repository
            .create_history(history.clone())
            .await
            .unwrap();

        history
    }
}