use one_core::{
    model::history::HistoryMetadata, service::backup::dto::UnexportableEntitiesResponseDTO,
};
use uuid::Uuid;

use crate::utils::{
    context::TestContext, db_clients::histories::TestingHistoryParams, field_match::FieldHelpers,
};

#[tokio::test]
async fn test_get_history_entry_without_metadata() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
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
    let (context, organisation) = TestContext::new_with_organisation().await;
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
                        total_credentials: 1,
                        total_keys: 1,
                        total_dids: 1,
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
    assert!(resp["metadata"].is_null());
}

#[tokio::test]
async fn test_fail_to_get_history_entry_unknown_id() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.histories.get(Uuid::new_v4().into()).await;

    // THEN
    assert_eq!(resp.status(), 404);

    let resp = resp.json_value().await;
    assert_eq!(resp["code"], "BR_0100");
}
