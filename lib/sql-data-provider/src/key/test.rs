use super::KeyProvider;
use sea_orm::{ActiveModelTrait, Set};
use std::sync::Arc;

use time::OffsetDateTime;
use uuid::Uuid;

use crate::entity::key;
use one_core::model::key::{GetKeyQuery, KeyId, KeyRelations};
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
        public_key: Set(vec![]),
        private_key: Set(vec![]),
        storage_type: Set("test".to_string()),
        key_type: Set("test".to_string()),
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

struct TestListSetup {
    pub db: sea_orm::DatabaseConnection,
    pub organisation: Organisation,
    pub ids: Vec<Uuid>,
}

async fn setup_list() -> TestListSetup {
    let TestSetup {
        db,
        key_id,
        organisation,
    } = setup().await;

    let now = OffsetDateTime::now_utc();
    let key2_id = Uuid::new_v4();
    key::ActiveModel {
        id: Set(key2_id.to_string()),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set("test2".to_string()),
        public_key: Set(vec![]),
        private_key: Set(vec![]),
        storage_type: Set("test2".to_string()),
        key_type: Set("test2".to_string()),
        organisation_id: Set(organisation.id.to_string()),
    }
    .insert(&db)
    .await
    .unwrap();

    TestListSetup {
        db,
        organisation,
        ids: vec![key_id, key2_id],
    }
}

#[tokio::test]
async fn test_create_key_success() {
    let organisation_repository = MockOrganisationRepository::default();

    let TestSetup {
        db, organisation, ..
    } = setup().await;

    let provider = KeyProvider {
        db: db.clone(),
        organisation_repository: Arc::new(organisation_repository),
    };

    let now = OffsetDateTime::now_utc();

    let id = Uuid::new_v4();
    let result = provider
        .create_key(Key {
            id: id.to_owned(),
            created_date: now,
            last_modified: now,
            public_key: vec![],
            name: "name".to_string(),
            private_key: vec![],
            storage_type: "INTERNAL".to_string(),
            key_type: "RSA_4096".to_string(),
            organisation: Some(organisation),
        })
        .await;

    assert!(result.is_ok());
    assert_eq!(id, result.unwrap());
}

#[tokio::test]
async fn test_get_key_success() {
    let organisation_repository = MockOrganisationRepository::default();

    let TestSetup { db, key_id, .. } = setup().await;

    let provider = KeyProvider {
        db: db.clone(),
        organisation_repository: Arc::new(organisation_repository),
    };

    let result = provider
        .get_key(&key_id, &KeyRelations { organisation: None })
        .await;

    assert!(result.is_ok());
    assert_eq!(key_id, result.unwrap().id);
}

#[tokio::test]
async fn test_get_key_list_success() {
    let organisation_repository = MockOrganisationRepository::default();

    let TestListSetup {
        db,
        organisation,
        ids,
    } = setup_list().await;

    let provider = KeyProvider {
        db: db.clone(),
        organisation_repository: Arc::new(organisation_repository),
    };

    let query_params = GetKeyQuery {
        page: 0,
        page_size: 5,
        sort: None,
        sort_direction: None,
        name: None,
        organisation_id: organisation.id.to_string(),
        exact: None,
    };

    let result = provider.get_key_list(query_params).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 2);
    assert_eq!(data.values.len(), 2);

    assert!(data.values.iter().all(|key| ids.contains(&key.id)));
}
