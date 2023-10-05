use super::KeyProvider;

use time::OffsetDateTime;
use uuid::Uuid;

use one_core::{
    model::{key::Key, organisation::Organisation},
    repository::key_repository::KeyRepository,
};

use crate::test_utilities::{
    insert_organisation_to_database, setup_test_data_layer_and_connection,
};

struct TestSetup {
    pub db: sea_orm::DatabaseConnection,
    pub organisation: Organisation,
}

async fn setup_empty() -> TestSetup {
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

    TestSetup { db, organisation }
}

#[tokio::test]
async fn test_create_key_success() {
    let TestSetup {
        db, organisation, ..
    } = setup_empty().await;

    let provider = KeyProvider { db: db.clone() };

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
