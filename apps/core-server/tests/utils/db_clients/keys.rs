use std::sync::Arc;

use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::repository::key_repository::KeyRepository;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::TestingKeyParams;

pub struct KeysDB {
    repository: Arc<dyn KeyRepository>,
}

impl KeysDB {
    pub fn new(repository: Arc<dyn KeyRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(&self, organisation: &Organisation, params: TestingKeyParams) -> Key {
        let now = OffsetDateTime::now_utc();

        let key = Key {
            id: params.id.unwrap_or(Uuid::new_v4()),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            public_key: params.public_key.unwrap_or_default(),
            name: params.name.unwrap_or_default(),
            key_reference: params.key_reference.unwrap_or_default(),
            storage_type: params.storage_type.unwrap_or_default(),
            key_type: params.key_type.unwrap_or_default(),
            organisation: Some(organisation.to_owned()),
        };

        self.repository.create_key(key.clone()).await.unwrap();

        key
    }
}

pub fn eddsa_testing_params() -> TestingKeyParams {
    TestingKeyParams {
        key_type: Some("EDDSA".to_string()),
        storage_type: Some("INTERNAL".to_string()),

        // multibase: z6MkiTpd8kEpGx2yshsgVgtdNWYykfLBTc3GVA26tew3n2y1
        public_key: Some(vec![
            59, 147, 149, 138, 47, 163, 27, 121, 194, 202, 219, 189, 55, 120, 146, 135, 204, 49,
            120, 110, 206, 132, 78, 224, 94, 221, 61, 161, 171, 61, 238, 124,
        ]),
        key_reference: Some(vec![
            62, 32, 184, 150, 100, 131, 44, 102, 69, 60, 205, 5, 0, 0, 0, 0, 0, 0, 0, 32, 165, 39,
            201, 216, 231, 240, 137, 12, 128, 49, 56, 255, 170, 204, 126, 54, 82, 73, 7, 68, 21,
            252, 40, 65, 56, 169, 144, 236, 15, 50, 143, 27, 221, 239, 195, 169, 242, 159, 95, 87,
            87, 124, 188, 24, 103, 205, 137, 162,
        ]),
        ..Default::default()
    }
}
