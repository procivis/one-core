use std::vec;

use one_core::model::remote_entity_cache::{
    CacheType, RemoteEntityCacheEntry, RemoteEntityCacheRelations,
};
use one_core::repository::remote_entity_cache_repository::RemoteEntityCacheRepository;
use sea_orm::{ActiveModelTrait, DatabaseConnection, DbErr, EntityTrait, Set};
use shared_types::RemoteEntityCacheEntryId;
use time::OffsetDateTime;
use uuid::Uuid;

use super::RemoteEntityCacheProvider;
use crate::entity::remote_entity_cache;
use crate::test_utilities::{get_dummy_date, setup_test_data_layer_and_connection};

struct TestSetup {
    pub provider: RemoteEntityCacheProvider,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        provider: RemoteEntityCacheProvider { db: db.clone() },
        db,
    }
}

struct TestSetupWithContext {
    pub db: sea_orm::DatabaseConnection,
    pub provider: RemoteEntityCacheProvider,
    pub id: RemoteEntityCacheEntryId,
    pub context: Vec<u8>,
    pub url: String,
    pub hit_counter: u32,
}

async fn setup_with_context() -> TestSetupWithContext {
    let setup = setup().await;

    let context = vec![1, 2, 3];
    let url = "http://www.host.co";
    let hit_counter = 0u32;

    let id = insert_json_ld_context(&setup.db, &context, url, hit_counter, None)
        .await
        .unwrap();

    TestSetupWithContext {
        db: setup.db,
        provider: setup.provider,
        id,
        context,
        url: url.to_string(),
        hit_counter,
    }
}

pub async fn insert_json_ld_context(
    database: &DatabaseConnection,
    context: &[u8],
    url: &str,
    hit_counter: u32,
    last_modified: Option<OffsetDateTime>,
) -> Result<RemoteEntityCacheEntryId, DbErr> {
    let json_ld_context = remote_entity_cache::ActiveModel {
        id: Set(Uuid::new_v4().into()),
        created_date: Set(get_dummy_date()),
        last_modified: Set(last_modified.unwrap_or(get_dummy_date())),
        key: Set(url.to_string()),
        value: Set(context.to_owned()),
        hit_counter: Set(hit_counter),
        r#type: Set(remote_entity_cache::CacheType::JsonLdContext),
        media_type: Set(None),
        persistent: Set(false),
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
    let context = RemoteEntityCacheEntry {
        id: id.into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        value: vec![0, 1, 2, 3],
        key: "http://www.host.co".parse().unwrap(),
        hit_counter: 1234,
        r#type: CacheType::JsonLdContext,
        media_type: None,
        persistent: false,
    };

    let result = setup.provider.create(context).await.unwrap();
    assert_eq!(id, result.into());

    let model = get_json_ld_context(&setup.db, &id.into()).await.unwrap();
    assert_eq!(model.value, [0, 1, 2, 3]);
    assert_eq!(model.key, "http://www.host.co");
    assert_eq!(model.hit_counter, 1234);
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
    assert_eq!(setup.hit_counter, result.hit_counter);
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

    setup
        .provider
        .update(RemoteEntityCacheEntry {
            id: setup.id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            value: vec![1, 2, 3, 4, 5, 6],
            key: "http://127.0.0.1".parse().unwrap(),
            hit_counter: 1234,
            r#type: CacheType::JsonLdContext,
            media_type: None,
            persistent: false,
        })
        .await
        .unwrap();

    let context = get_json_ld_context(&setup.db, &setup.id).await.unwrap();
    assert_eq!([1u8, 2, 3, 4, 5, 6], *context.value);
    assert_eq!("http://127.0.0.1", context.key);
    assert_eq!(1234, context.hit_counter);
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
    assert_eq!(setup.hit_counter, result.hit_counter);
}

#[tokio::test]
async fn test_delete_oldest_context_success_simple() {
    let setup = setup_with_context().await;

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();

    let result = setup
        .provider
        .get_by_id(&setup.id, &RemoteEntityCacheRelations::default())
        .await
        .unwrap();
    assert!(result.is_none());

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();
}

#[tokio::test]
async fn test_delete_oldest_context_success_complex_select_lowest_hit_count_and_modification_time()
{
    let setup = setup().await;

    let hit_count_100_modified_years_ago = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1",
        100,
        Some(get_dummy_date()),
    )
    .await
    .unwrap();

    let hit_count_100_modified_now = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1",
        100,
        Some(OffsetDateTime::now_utc()),
    )
    .await
    .unwrap();

    let hit_count_0_modified_years_ago = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1",
        0,
        Some(get_dummy_date()),
    )
    .await
    .unwrap();

    let hit_count_0_modified_now = insert_json_ld_context(
        &setup.db,
        &[0, 1, 2, 3],
        "http://127.0.0.1",
        0,
        Some(OffsetDateTime::now_utc()),
    )
    .await
    .unwrap();

    let c1 = get_json_ld_context(&setup.db, &hit_count_0_modified_years_ago).await;
    let c2 = get_json_ld_context(&setup.db, &hit_count_0_modified_now).await;
    let c3 = get_json_ld_context(&setup.db, &hit_count_100_modified_years_ago).await;
    let c4 = get_json_ld_context(&setup.db, &hit_count_100_modified_now).await;
    assert!(c1.is_ok());
    assert!(c2.is_ok());
    assert!(c3.is_ok());
    assert!(c4.is_ok());

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();
    let c1 = get_json_ld_context(&setup.db, &hit_count_0_modified_years_ago).await;
    let c2 = get_json_ld_context(&setup.db, &hit_count_0_modified_now).await;
    let c3 = get_json_ld_context(&setup.db, &hit_count_100_modified_years_ago).await;
    let c4 = get_json_ld_context(&setup.db, &hit_count_100_modified_now).await;
    assert!(matches!(c1, Err(DbErr::RecordNotFound(_))));
    assert!(c2.is_ok());
    assert!(c3.is_ok());
    assert!(c4.is_ok());

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();
    let c1 = get_json_ld_context(&setup.db, &hit_count_0_modified_years_ago).await;
    let c2 = get_json_ld_context(&setup.db, &hit_count_0_modified_now).await;
    let c3 = get_json_ld_context(&setup.db, &hit_count_100_modified_years_ago).await;
    let c4 = get_json_ld_context(&setup.db, &hit_count_100_modified_now).await;
    assert!(matches!(c1, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c2, Err(DbErr::RecordNotFound(_))));
    assert!(c3.is_ok());
    assert!(c4.is_ok());

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();
    let c1 = get_json_ld_context(&setup.db, &hit_count_0_modified_years_ago).await;
    let c2 = get_json_ld_context(&setup.db, &hit_count_0_modified_now).await;
    let c3 = get_json_ld_context(&setup.db, &hit_count_100_modified_years_ago).await;
    let c4 = get_json_ld_context(&setup.db, &hit_count_100_modified_now).await;
    assert!(matches!(c1, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c2, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c3, Err(DbErr::RecordNotFound(_))));
    assert!(c4.is_ok());

    setup
        .provider
        .delete_oldest(CacheType::JsonLdContext)
        .await
        .unwrap();
    let c1 = get_json_ld_context(&setup.db, &hit_count_0_modified_years_ago).await;
    let c2 = get_json_ld_context(&setup.db, &hit_count_0_modified_now).await;
    let c3 = get_json_ld_context(&setup.db, &hit_count_100_modified_years_ago).await;
    let c4 = get_json_ld_context(&setup.db, &hit_count_100_modified_now).await;
    assert!(matches!(c1, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c2, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c3, Err(DbErr::RecordNotFound(_))));
    assert!(matches!(c4, Err(DbErr::RecordNotFound(_))));
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

    let _ = insert_json_ld_context(&setup.db, &[1, 2, 3], "http://1.2.3.4", 0, None)
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
