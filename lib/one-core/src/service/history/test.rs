use super::HistoryService;

use std::sync::Arc;

use crate::{
    model::history::GetHistoryList, repository::history_repository::MockHistoryRepository,
};

fn setup_service(history_repository: MockHistoryRepository) -> HistoryService {
    HistoryService::new(Arc::new(history_repository))
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
