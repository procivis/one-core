use std::sync::Arc;

use one_core::model::blob::{Blob, BlobType, UpdateBlobRequest};
use one_core::repository::blob_repository::BlobRepository;
use sea_orm::{DatabaseConnection, EntityTrait};
use shared_types::BlobId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::blob::BlobProvider;
use crate::entity;
use crate::test_utilities::{get_dummy_date, setup_test_data_layer_and_connection};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub db: DatabaseConnection,
    pub provider: BlobProvider,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        db: db.clone(),
        provider: BlobProvider {
            db: Arc::new(TransactionManagerImpl::new(db)),
        },
    }
}

#[tokio::test]
async fn test_create_blob() {
    // given
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let blob = dummy_blob(id);

    // when
    let result = setup.provider.create(blob).await;

    // then
    assert!(result.is_ok());

    assert_eq!(
        entity::blob::Entity::find()
            .all(&setup.db)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn test_get_blob() {
    // given
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let blob = dummy_blob(id);

    insert_blob(&setup.db, &blob).await;

    // when
    let result = setup.provider.get(&id).await.unwrap();

    // then
    assert!(result.is_some());
    assert_eq!(blob, result.unwrap());
}

#[tokio::test]
async fn test_update_blob() {
    // given
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let blob = dummy_blob(id);
    insert_blob(&setup.db, &blob).await;
    let new_value = vec![5, 4, 3, 2, 1];

    // when
    setup
        .provider
        .update(
            &id,
            UpdateBlobRequest {
                value: Some(new_value.clone()),
            },
        )
        .await
        .unwrap();

    // then
    let entity = entity::blob::Entity::find_by_id(id)
        .one(&setup.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(entity.id, id);
    assert_eq!(entity.value, new_value);
    assert_ne!(entity.last_modified, blob.last_modified);
}

#[tokio::test]
async fn test_delete_blob() {
    // given
    let setup = setup().await;
    let id = Uuid::new_v4().into();

    let blob = dummy_blob(id);
    insert_blob(&setup.db, &blob).await;

    // when
    let result = setup.provider.delete(&id).await;

    // then
    assert!(result.is_ok());

    assert_eq!(
        entity::blob::Entity::find()
            .all(&setup.db)
            .await
            .unwrap()
            .len(),
        0
    );
}

fn dummy_blob(id: BlobId) -> Blob {
    Blob {
        id,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: vec![0, 1, 2, 3, 4, 5],
        r#type: BlobType::Credential,
    }
}

async fn insert_blob(db: &DatabaseConnection, blob: &Blob) {
    entity::blob::Entity::insert::<entity::blob::ActiveModel>(blob.clone().into())
        .exec(db)
        .await
        .unwrap();
}
