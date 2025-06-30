use std::sync::Arc;

use one_core::model::trust_anchor::TrustAnchor;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use one_dto_mapper::Into;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct TrustAnchorDB {
    repository: Arc<dyn TrustAnchorRepository>,
}

#[derive(Debug, Into)]
#[into(TrustAnchor)]
pub struct TestingTrustAnchorParams {
    pub id: Uuid,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub r#type: String,
    pub publisher_reference: String,
    pub is_publisher: bool,
}

impl Default for TestingTrustAnchorParams {
    fn default() -> Self {
        let id = Uuid::new_v4();
        Self {
            id,
            name: format!("trust anchor {id}"),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            r#type: "SIMPLE_TRUST_LIST".to_string(),
            publisher_reference: format!("publisher reference {id}"),
            is_publisher: true,
        }
    }
}

impl TrustAnchorDB {
    pub fn new(repository: Arc<dyn TrustAnchorRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, params: TestingTrustAnchorParams) -> TrustAnchor {
        let trust_anchor = TrustAnchor::from(params);
        self.repository.create(trust_anchor.clone()).await.unwrap();
        trust_anchor
    }
}
