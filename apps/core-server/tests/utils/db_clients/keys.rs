use one_core::model::key::KeyRelations;
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::key_repository::KeyRepository;
use one_providers::common_models::key::Key;
use shared_types::KeyId;
use std::sync::Arc;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{unwrap_or_random, TestingKeyParams};

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
            id: params.id.unwrap_or(Uuid::new_v4().into()).into(),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            public_key: params.public_key.unwrap_or_default(),
            name: unwrap_or_random(params.name),
            key_reference: params.key_reference.unwrap_or_default(),
            storage_type: params.storage_type.unwrap_or_default(),
            key_type: params.key_type.unwrap_or_default(),
            organisation: Some(organisation.to_owned().into()),
        };

        self.repository.create_key(key.clone()).await.unwrap();

        self.get(&key.id.to_owned().into()).await
    }

    pub async fn get(&self, id: &KeyId) -> Key {
        self.repository
            .get_key(
                &id.to_owned().into(),
                &KeyRelations {
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
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

        // multibase: z6MkuJnXWiLNmV3SooQ72iDYmUE1sz5HTCXWhKNhDZuqk4Rj
        public_key: Some(vec![
            220, 179, 138, 196, 30, 98, 147, 213, 162, 146, 4, 38, 168, 209, 109, 154, 235, 205,
            11, 65, 76, 20, 85, 87, 175, 160, 19, 86, 130, 254, 145, 62,
        ]),
        key_reference: Some(vec![
            137, 117, 80, 218, 12, 180, 214, 27, 139, 193, 39, 109, 0, 0, 0, 0, 0, 0, 0, 64, 27,
            191, 169, 38, 174, 140, 216, 204, 199, 58, 207, 176, 104, 109, 111, 51, 113, 53, 229,
            160, 125, 208, 198, 14, 199, 255, 116, 28, 11, 74, 4, 69, 215, 159, 141, 82, 169, 237,
            124, 127, 162, 116, 118, 69, 243, 155, 160, 38, 198, 175, 156, 153, 77, 15, 10, 73,
            103, 31, 60, 21, 33, 76, 209, 173, 243, 252, 126, 244, 144, 37, 80, 7, 74, 235, 155,
            135, 54, 94, 173, 118,
        ]),
        ..Default::default()
    }
}
