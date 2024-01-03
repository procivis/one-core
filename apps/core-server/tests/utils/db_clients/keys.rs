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

pub fn es256_testing_params() -> TestingKeyParams {
    TestingKeyParams {
        key_type: Some("ES256".to_string()),
        storage_type: Some("INTERNAL".to_string()),

        // multibase: zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ
        public_key: Some(vec![
            2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0, 12,
            229, 151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
        ]),
        key_reference: Some(vec![
            191, 117, 227, 19, 61, 61, 70, 152, 133, 158, 83, 244, 0, 0, 0, 0, 0, 0, 0, 32, 1, 0,
            223, 243, 57, 200, 101, 206, 133, 43, 169, 194, 153, 38, 105, 35, 100, 79, 106, 61, 68,
            62, 9, 96, 48, 202, 28, 74, 43, 89, 96, 100, 154, 148, 140, 180, 17, 135, 78, 216, 169,
            229, 27, 196, 181, 163, 95, 116,
        ]),
        ..Default::default()
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
