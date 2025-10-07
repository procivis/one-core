use one_core::model::history::{HistoryErrorMetadata, HistoryMetadata};
use one_core::service::backup::dto::UnexportableEntitiesResponseDTO;
use one_core::service::error::ErrorCode;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_history_entry_without_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let history = context
        .db
        .histories
        .create(&organisation, Default::default())
        .await;

    // WHEN
    let resp = context.api.histories.get(history.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&history.id);
    assert!(resp["metadata"].is_null());
}

#[tokio::test]
async fn test_get_history_entry_with_unexportable_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let history = context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                metadata: Some(HistoryMetadata::UnexportableEntities(
                    UnexportableEntitiesResponseDTO {
                        credentials: vec![],
                        keys: vec![],
                        dids: vec![],
                        identifiers: vec![],
                        history: vec![],
                        wallet_unit_attestation: vec![],
                        total_credentials: 3,
                        total_keys: 1,
                        total_dids: 2,
                        total_identifiers: 0,
                        total_histories: 1,
                        total_wallet_unit_attestations: 0,
                    },
                )),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.histories.get(history.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&history.id);
    assert_eq!(resp["metadata"]["UnexportableEntities"]["total_keys"], 1);
    assert_eq!(resp["metadata"]["UnexportableEntities"]["total_dids"], 2);
    assert_eq!(
        resp["metadata"]["UnexportableEntities"]["total_credentials"],
        3
    );
}

#[tokio::test]
async fn test_get_history_entry_with_error_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let history = context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                metadata: Some(HistoryMetadata::ErrorMetadata(HistoryErrorMetadata {
                    error_code: ErrorCode::BR_0000,
                    message: "Test error".to_string(),
                })),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.histories.get(history.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&history.id);
    assert_eq!(resp["metadata"]["ErrorMetadata"]["error_code"], "BR_0000");
    assert_eq!(resp["metadata"]["ErrorMetadata"]["message"], "Test error");
}

#[tokio::test]
async fn test_fail_to_get_history_entry_unknown_id() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.histories.get(Uuid::new_v4().into()).await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0100", resp.error_code().await);
}

#[tokio::test]
async fn test_get_history_entry_with_target() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let history = context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                target: Some("Foo".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.histories.get(history.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&history.id);
    resp["target"].assert_eq(&"Foo".to_string());
}

#[tokio::test]
async fn test_get_history_entry_with_user() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let history = context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                user: Some("TestUser".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.histories.get(history.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&history.id);
    resp["user"].assert_eq(&"TestUser".to_string());
}
