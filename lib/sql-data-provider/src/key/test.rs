use std::sync::Arc;

use one_core::model::key::{Key, KeyFilterValue, KeyListQuery, KeyRelations};
use one_core::model::list_filter::ListFilterValue;
use one_core::model::list_query::ListPagination;
use one_core::model::organisation::Organisation;
use one_core::repository::key_repository::KeyRepository;
use one_core::repository::organisation_repository::MockOrganisationRepository;
use sea_orm::ActiveValue::NotSet;
use sea_orm::{ActiveModelTrait, Set};
use shared_types::KeyId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::KeyProvider;
use crate::entity::key;
use crate::test_utilities::{
    dummy_organisation, insert_organisation_to_database, setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub key_id: KeyId,
    pub organisation: Organisation,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    let organisation_id = insert_organisation_to_database(&db, None, None)
        .await
        .unwrap();

    let now = OffsetDateTime::now_utc();
    let organisation = dummy_organisation(Some(organisation_id));

    let key_id = Uuid::new_v4().into();
    key::ActiveModel {
        id: Set(key_id),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set("test".to_string()),
        public_key: Set(vec![]),
        key_reference: Set(vec![]),
        storage_type: Set("test".to_string()),
        key_type: Set("test".to_string()),
        organisation_id: Set(organisation_id),
        deleted_at: NotSet,
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
    pub ids: Vec<KeyId>,
}

async fn setup_list() -> TestListSetup {
    let TestSetup {
        db,
        key_id,
        organisation,
    } = setup().await;

    let now = OffsetDateTime::now_utc();
    let key2_id = Uuid::new_v4().into();
    key::ActiveModel {
        id: Set(key2_id),
        created_date: Set(now),
        last_modified: Set(now),
        name: Set("test2".to_string()),
        public_key: Set(vec![]),
        key_reference: Set(vec![]),
        storage_type: Set("test2".to_string()),
        key_type: Set("test2".to_string()),
        organisation_id: Set(organisation.id),
        deleted_at: NotSet,
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

    let id = Uuid::new_v4().into();
    let result = provider
        .create_key(Key {
            id,
            created_date: now,
            last_modified: now,
            public_key: vec![],
            name: "name".to_string(),
            key_reference: vec![],
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
        .await
        .unwrap()
        .unwrap();

    assert_eq!(key_id, result.id);
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

    let query = KeyListQuery {
        pagination: Some(ListPagination {
            page: 0,
            page_size: 5,
        }),
        sorting: None,
        filtering: Some(KeyFilterValue::OrganisationId(organisation.id).condition()),
        include: None,
    };

    let result = provider.get_key_list(query).await;
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.total_pages, 1);
    assert_eq!(data.total_items, 2);
    assert_eq!(data.values.len(), 2);

    assert!(data.values.iter().all(|key| ids.contains(&key.id)));
}
