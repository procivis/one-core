use std::sync::Arc;

use one_core::model::trust_anchor::TrustAnchor;
use one_core::repository::trust_anchor_repository::TrustAnchorRepository;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct TrustAnchorDB {
    repository: Arc<dyn TrustAnchorRepository>,
}

impl TrustAnchorDB {
    pub fn new(repository: Arc<dyn TrustAnchorRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, name: &str, r#type: &str, is_publisher: bool) -> TrustAnchor {
        let trust_anchor = TrustAnchor {
            id: Uuid::new_v4().into(),
            name: name.into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            r#type: r#type.into(),
            publisher_reference: "123".to_string(),
            is_publisher,
        };

        self.repository.create(trust_anchor.clone()).await.unwrap();

        trust_anchor
    }
}
