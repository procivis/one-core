use std::vec;

use one_core::model::remote_entity_cache::{
    CacheType, RemoteEntityCacheEntry, RemoteEntityCacheRelations,
};
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::RemoteEntityCacheEntryId;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use super::RemoteEntityCacheProvider;
use crate::entity::remote_entity_cache;
use crate::test_utilities::{get_dummy_date, setup_test_data_layer_and_connection};
use crate::transaction_context::TransactionManagerImpl;

struct TestSetup {
    pub provider: RemoteEntityCacheProvider,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        provider: RemoteEntityCacheProvider {
            db: TransactionManagerImpl::new(db.clone()),
        },
        db,
    }
}

struct TestSetupWithContext {
    pub db: sea_orm::DatabaseConnection,
    pub provider: RemoteEntityCacheProvider,
    pub id: RemoteEntityCacheEntryId,
    pub context: Vec<u8>,
    pub url: String,
}

async fn setup_with_context() -> TestSetupWithContext {
    let setup = setup().await;

    let context = vec![1, 2, 3];
    let url = "http://www.host.co";

    let id = insert_json_ld_context(&setup.db, &context, url, OffsetDateTime::now_utc(), None)
        .await
        .unwrap();

    TestSetupWithContext {
        db: setup.db,
        provider: setup.provider,
        id,
        context,
        url: url.to_string(),
    }
}

async fn insert_json_ld_context(
    database: &DatabaseConnection,
    context: &[u8],
    url: &str,
    last_used: OffsetDateTime,
    expiration_date: Option<OffsetDateTime>,
) -> Result<RemoteEntityCacheEntryId, DbErr> {
    let json_ld_context = remote_entity_cache::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(last_used),
        expiration_date: Set(expiration_date),
        key: Set(url.to_string()),
        value: Set(context.to_owned()),
        last_used: Set(last_used),
        r#type: Set(remote_entity_cache::CacheType::JsonLdContext),
        media_type: Set(None),
    }
    .insert(database)
    .await?;

    Ok(json_ld_context.id)
}

pub async fn get_json_ld_context(
    database: &DatabaseConnection,
    id: &RemoteEntityCacheEntryId,
) -> Result<remote_entity_cache::Model, DbErr> {
    remote_entity_cache::Entity::find_by_id(id)
        .one(database)
        .await?
        .ok_or(DbErr::RecordNotFound(String::default()))
}

#[tokio::test]
async fn test_create_context() {
    let setup = setup().await;

    let id = Uuid::new_v4();
    let timestamp = OffsetDateTime::now_utc();
    let context = RemoteEntityCacheEntry {
        id: id.into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        expiration_date: Some(OffsetDateTime::now_utc() + Duration::days(1)),
        value: vec![0, 1, 2, 3],
        key: "http://www.host.co".parse().unwrap(),
        last_used: timestamp,
        r#type: CacheType::JsonLdContext,
        media_type: None,
    };

    let result = setup.provider.create(context).await.unwrap();
    assert_eq!(id, Uuid::from(result));

    let model = get_json_ld_context(&setup.db, &id.into()).await.unwrap();
    assert_eq!(model.value, [0, 1, 2, 3]);
    assert_eq!(model.key, "http://www.host.co");
    assert_eq!(model.last_used, timestamp);
}

#[tokio::test]
async fn test_get_context_success() {
    let setup = setup_with_context().await;

    let result = setup
        .provider
        .get_by_id(&setup.id, &RemoteEntityCacheRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(setup.context, result.value);
    assert_eq!(setup.url, result.key);
}

#[tokio::test]
async fn test_get_context_failed_wrong_id() {
    let setup = setup_with_context().await;

    let result = setup
        .provider
        .get_by_id(
            &Uuid::new_v4().into(),
            &RemoteEntityCacheRelations::default(),
        )
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_context_success() {
    let setup = setup_with_context().await;

    let last_used = OffsetDateTime::now_utc() + Duration::days(2);
    setup
        .provider
        .update(RemoteEntityCacheEntry {
            id: setup.id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            expiration_date: Some(OffsetDateTime::now_utc() + Duration::days(1)),
            value: vec![1, 2, 3, 4, 5, 6],
            key: "http://127.0.0.1".parse().unwrap(),
            last_used,
            r#type: CacheType::JsonLdContext,
            media_type: None,
        })
        .await
        .unwrap();

    let context = get_json_ld_context(&setup.db, &setup.id).await.unwrap();
    assert_eq!([1u8, 2, 3, 4, 5, 6], *context.value);
    assert_eq!("http://127.0.0.1", context.key);
    assert_eq!(last_used, context.last_used);
}

#[tokio::test]
async fn test_get_context_by_url_success() {
    let setup = setup_with_context().await;

    let result = setup
        .provider
        .get_by_key("http://www.host.co")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(setup.context, result.value);
    assert_eq!(setup.url, result.key);
}

#[tokio::test]
async fn test_delete_oldest_context_success() {
    let setup = setup().await;

    let days_ago = OffsetDateTime::now_utc() - Duration::days(2);

    let persistent = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1/0",
        days_ago,
        None,
    )
    .await
    .unwrap();

    let expired = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1/1",
        days_ago,
        Some(days_ago),
    )
    .await
    .unwrap();

    let used_days_ago = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1/2",
        days_ago,
        Some(OffsetDateTime::now_utc() + Duration::days(1)),
    )
    .await
    .unwrap();

    let used_now = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1/3",
        OffsetDateTime::now_utc(),
        Some(OffsetDateTime::now_utc() + Duration::days(1)),
    )
    .await
    .unwrap();

    setup
        .provider
        .delete_expired_or_least_used(CacheType::JsonLdContext, 2)
        .await
        .unwrap();

    get_json_ld_context(&setup.db, &persistent).await.unwrap();
    let c1 = get_json_ld_context(&setup.db, &expired).await;
    assert!(matches!(c1, Err(DbErr::RecordNotFound(_))));
    let c2 = get_json_ld_context(&setup.db, &used_days_ago).await;
    assert!(matches!(c2, Err(DbErr::RecordNotFound(_))));
    get_json_ld_context(&setup.db, &used_now).await.unwrap();
}

#[tokio::test]
async fn test_get_repository_size_success() {
    let setup = setup_with_context().await;

    assert_eq!(
        1,
        setup
            .provider
            .get_repository_size(CacheType::JsonLdContext)
            .await
            .unwrap()
    );

    insert_json_ld_context(
        &setup.db,
        &[1, 2, 3],
        "http://1.2.3.4",
        get_dummy_date(),
        None,
    )
    .await
    .unwrap();

    assert_eq!(
        2,
        setup
            .provider
            .get_repository_size(CacheType::JsonLdContext)
            .await
            .unwrap()
    );
}
