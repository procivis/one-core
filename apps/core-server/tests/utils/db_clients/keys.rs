use std::sync::Arc;

use hex_literal::hex;
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::repository::key_repository::KeyRepository;
use shared_types::KeyId;
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
            id: params.id.unwrap_or(Uuid::new_v4().into()),
            created_date: params.created_date.unwrap_or(now),
            last_modified: params.last_modified.unwrap_or(now),
            public_key: params.public_key.unwrap_or_default(),
            name: unwrap_or_random(params.name),
            key_reference: params.key_reference.unwrap_or_default(),
            storage_type: params.storage_type.unwrap_or_default(),
            key_type: params.key_type.unwrap_or_default(),
            organisation: Some(organisation.to_owned()),
        };

        self.repository.create_key(key.clone()).await.unwrap();

        self.get(&key.id).await
    }

    pub async fn get(&self, id: &KeyId) -> Key {
        self.repository
            .get_key(
                id,
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

        public_key: Some(
            hex!("4a0449c993ee8bc94f2d70c498230f26be8d3a1365b82554d26513f525abef5f").to_vec(),
        ),
        key_reference: Some(
            hex!("8f6107bff565c52559d1c3cb0000000000000040756ccec86ddd9a982597806376ad3bb339619d0e406b68c85923dbeb0291fff60ace6c5e07eba0fbaaa3caf3c117fac446fa9418c8af1996e8cc727b793a2b787b76ef373358bf44016c3ab6c062df85").to_vec()
        ),
        ..Default::default()
    }
}
