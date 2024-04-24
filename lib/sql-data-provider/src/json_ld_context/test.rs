use std::str::FromStr;
use std::vec;
use url::Url;

use one_core::model::json_ld_context::{JsonLdContext, JsonLdContextRelations};
use one_core::repository::json_ld_context_repository::JsonLdContextRepository;
use shared_types::JsonLdContextId;
use uuid::Uuid;

use crate::test_utilities::{
    get_dummy_date, get_json_ld_context, insert_json_ld_context,
    setup_test_data_layer_and_connection,
};

use super::JsonLdContextProvider;

struct TestSetup {
    pub provider: JsonLdContextProvider,
    pub db: sea_orm::DatabaseConnection,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    let db = data_layer.db;

    TestSetup {
        provider: JsonLdContextProvider { db: db.clone() },
        db,
    }
}

struct TestSetupWithContext {
    pub db: sea_orm::DatabaseConnection,
    pub provider: JsonLdContextProvider,
    pub id: JsonLdContextId,
    pub context: Vec<u8>,
    pub url: Url,
    pub hit_counter: u32,
}

async fn setup_with_context() -> TestSetupWithContext {
    let setup = setup().await;

    let context = vec![1, 2, 3];
    let url = Url::from_str("http://www.host.co").unwrap();
    let hit_counter = 0u32;

    let id = insert_json_ld_context(&setup.db, &context, url.as_str(), hit_counter)
        .await
        .unwrap();

    TestSetupWithContext {
        db: setup.db,
        provider: setup.provider,
        id,
        context,
        url,
        hit_counter,
    }
}

#[tokio::test]
async fn test_create_context() {
    let setup = setup().await;

    let id = Uuid::new_v4();
    let context = JsonLdContext {
        id: id.into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        context: vec![0, 1, 2, 3],
        url: "http://www.host.co".parse().unwrap(),
        hit_counter: 1234,
    };

    let result = setup
        .provider
        .create_json_ld_context(context)
        .await
        .unwrap();
    assert_eq!(id, result.into());

    let model = get_json_ld_context(&setup.db, &id.into()).await.unwrap();
    assert_eq!(model.context, [0, 1, 2, 3]);
    assert_eq!(model.url, "http://www.host.co/");
    assert_eq!(model.hit_counter, 1234);
}

#[tokio::test]
async fn test_get_context_success() {
    let setup = setup_with_context().await;

    let result = setup
        .provider
        .get_json_ld_context(&setup.id, &JsonLdContextRelations::default())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(setup.context, result.context);
    assert_eq!(setup.url, result.url);
    assert_eq!(setup.hit_counter, result.hit_counter);
}

#[tokio::test]
async fn test_get_context_failed_wrong_id() {
    let setup = setup_with_context().await;

    let result = setup
        .provider
        .get_json_ld_context(&Uuid::new_v4().into(), &JsonLdContextRelations::default())
        .await
        .unwrap();

    assert!(result.is_none());
}

#[tokio::test]
async fn test_update_context_success() {
    let setup = setup_with_context().await;

    setup
        .provider
        .update_json_ld_context(JsonLdContext {
            id: setup.id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            context: vec![1, 2, 3, 4, 5, 6],
            url: "http://127.0.0.1/".parse().unwrap(),
            hit_counter: 1234,
        })
        .await
        .unwrap();

    let context = get_json_ld_context(&setup.db, &setup.id).await.unwrap();
    assert_eq!([1u8, 2, 3, 4, 5, 6], *context.context);
    assert_eq!("http://127.0.0.1/", context.url);
    assert_eq!(1234, context.hit_counter);
}
