use std::sync::Arc;

use super::HistoryService;
use crate::model::history::{GetHistoryList, HistoryAction, HistoryEntityType, HistorySource};
use crate::proto::session_provider::NoSessionProvider;
use crate::repository::history_repository::MockHistoryRepository;
use crate::service::error::{BusinessLogicError, ServiceError};
use crate::service::history::dto::CreateHistoryRequestDTO;

fn setup_service(history_repository: MockHistoryRepository) -> HistoryService {
    HistoryService::new(Arc::new(history_repository), Arc::new(NoSessionProvider))
}

#[tokio::test]
async fn test_get_list_success() {
    let mut history_repository = MockHistoryRepository::default();
    history_repository
        .expect_get_history_list()
        .times(1)
        .returning(|_query| {
            Ok(GetHistoryList {
                values: vec![],
                total_pages: 0,
                total_items: 0,
            })
        });

    let service = setup_service(history_repository);

    service.get_history_list(Default::default()).await.unwrap();
}

#[tokio::test]
async fn test_create_history_invalid_source() {
    let service = setup_service(MockHistoryRepository::default());

    assert!(matches!(
        service
            .create_history(CreateHistoryRequestDTO {
                source: HistorySource::Core,
                action: HistoryAction::Created,
                entity_type: HistoryEntityType::Organisation,
                name: "name".to_string(),
                entity_id: None,
                organisation_id: None,
                metadata: None,
                target: None,
            })
            .await,
        Err(ServiceError::BusinessLogic(
            BusinessLogicError::InvalidHistorySource
        ))
    ));
}
