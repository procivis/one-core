use super::KeyProvider;
use sea_orm::{ActiveModelTrait, Set};
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::key;
use one_core::model::key::{KeyId, KeyRelations};
use one_core::repository::mock::credential_repository::MockCredentialRepository;
use one_core::repository::mock::did_repository::MockDidRepository;
use one_core::{
    model::{key::Key, organisation::Organisation},
    repository::{
        key_repository::KeyRepository, mock::organisation_repository::MockOrganisationRepository,
    },
};

use crate::test_utilities::{
    insert_organisation_to_database, setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub key_id: KeyId,
    pub organisation: Organisation,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id =
        Uuid::parse_str(&insert_organisation_to_database(&db, None).await.unwrap()).unwrap();

    let now = OffsetDateTime::now_utc();
    let organisation = Organisation {
        id: organisation_id,
        created_date: now,
        last_modified: now,
    };

    let key_id = Uuid::new_v4();
    key::ActiveModel {
        id: Set(key_id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set("test".to_string()),
        public_key: Set("test".to_string()),
        private_key: Set(vec![]),
        storage_type: Set("test".to_string()),
        key_type: Set("test".to_string()),
        credential_id: Set(None),
        organisation_id: Set(organisation_id.to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    TestSetup {
        db,
        key_id,
        organisation,
    }
}

#[tokio::test]
async fn test_create_key_success() {
    let credential_repository = MockCredentialRepository::default();
    let did_repository = MockDidRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let TestSetup {
        db, organisation, ..
    } = setup().await;

    let provider = KeyProvider {
        db: db.clone(),
        credential_repository: Arc::new(credential_repository),
        did_repository: Arc::new(did_repository),
        organisation_repository: Arc::new(organisation_repository),
    };

    let now = OffsetDateTime::now_utc();

    let id = Uuid::new_v4();
    let result = provider
        .create_key(Key {
            id: id.to_owned(),
            created_date: now,
            last_modified: now,
            public_key: "".to_string(),
            name: "name".to_string(),
            private_key: vec![],
            storage_type: "INTERNAL".to_string(),
            key_type: "RSA_4096".to_string(),
            credential: None,
            dids: None,
            organisation: Some(organisation),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(id, result.unwrap());
}

#[tokio::test]
async fn test_get_key_success() {
    let credential_repository = MockCredentialRepository::default();
    let did_repository = MockDidRepository::default();
    let organisation_repository = MockOrganisationRepository::default();

    let TestSetup { db, key_id, .. } = setup().await;

    let provider = KeyProvider {
        db: db.clone(),
        credential_repository: Arc::new(credential_repository),
        did_repository: Arc::new(did_repository),
        organisation_repository: Arc::new(organisation_repository),
    };

    let result = provider
        .get_key(
            &key_id,
            &KeyRelations {
                credential: None,
                dids: None,
                organisation: None,
            },
        )
        .await;

    assert!(result.is_ok());
    assert_eq!(key_id, result.unwrap().id);
}
