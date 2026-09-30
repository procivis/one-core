use one_core::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use one_core::repository::localized_text_repository::LocalizedTextRepository;
use similar_asserts::assert_eq;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::localized_text::LocalizedTextProvider;
use crate::test_utilities::{get_dummy_date, setup_test_data_layer_and_connection};

struct TestSetup {
    pub provider: LocalizedTextProvider,
}

async fn setup() -> TestSetup {
    let data_layer = setup_test_data_layer_and_connection().await;
    TestSetup {
        provider: LocalizedTextProvider {
            db: data_layer.transaction_manager,
        },
    }
}

#[tokio::test]
async fn test_upsert_get_localized_text_success() {
    let TestSetup { provider } = setup().await;

    let localized_text = dummy_text();
    provider.upsert(localized_text.clone()).await.unwrap();
    let result = provider.get(&localized_text.entity_id).await.unwrap();

    assert_eq!(result.len(), 1);
    let stored = &result[0];
    let now = OffsetDateTime::now_utc();
    assert!(now - stored.created_date < std::time::Duration::from_secs(1));
    assert!(now - stored.last_modified < std::time::Duration::from_secs(1));
    assert!(eq_excluding_timestamps(stored, &localized_text));
}

#[tokio::test]
async fn test_upsert_update_get_localized_text_success() {
    let TestSetup { provider } = setup().await;

    let mut localized_text = dummy_text();
    provider.upsert(localized_text.clone()).await.unwrap();
    localized_text.value = "hello world updated".to_string();
    provider.upsert(localized_text.clone()).await.unwrap();
    let result = provider.get(&localized_text.entity_id).await.unwrap();
    assert!(result[0].last_modified > result[0].created_date);
    assert!(eq_excluding_timestamps(&localized_text, &result[0]));
}

#[tokio::test]
async fn test_upsert_many_get_localized_text_success() {
    let TestSetup { provider } = setup().await;

    let localized_text = dummy_text();
    let mut localized_text2 = localized_text.clone();
    localized_text2.lang = "de".to_string();
    localized_text2.value = "hello world two".to_string();
    let stale_text = LocalizedText {
        value: "stale value".to_string(),
        ..localized_text.clone()
    };
    provider
        .upsert_many(vec![
            stale_text,
            localized_text2.clone(),
            localized_text.clone(),
        ])
        .await
        .unwrap();
    let result = provider.get(&localized_text.entity_id).await.unwrap();

    assert_eq!(result.len(), 2);
    assert!(
        result
            .iter()
            .any(|t| eq_excluding_timestamps(&localized_text, t))
    );
    assert!(
        result
            .iter()
            .any(|t| eq_excluding_timestamps(&localized_text2, t))
    );
}

fn dummy_text() -> LocalizedText {
    LocalizedText {
        entity_id: Uuid::new_v4().into(),
        field: LocalizedTextField::Name,
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        lang: "en".to_string(),
        value: "hello world".to_string(),
        entity_type: LocalizedTextEntityType::CredentialSchema,
    }
}

fn eq_excluding_timestamps(a: &LocalizedText, b: &LocalizedText) -> bool {
    a.entity_id == b.entity_id
        && a.field == b.field
        && a.lang == b.lang
        && a.value == b.value
        && a.entity_type == b.entity_type
}
