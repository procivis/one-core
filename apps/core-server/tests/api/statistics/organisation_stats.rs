use one_core::model::history::{HistoryAction, HistoryEntityType};
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;

#[tokio::test]
async fn test_organisation_stats_empty() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .statistics
        .organisation_stats(None, OffsetDateTime::now_utc(), org.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["current"]["verificationCount"], 0);
    assert!(resp["previous"].is_null());
}

#[tokio::test]
async fn test_organisation_stats() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let now = OffsetDateTime::now_utc();
    context
        .db
        .histories
        .create(
            &org,
            TestingHistoryParams {
                action: Some(HistoryAction::Issued),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Credential),
                created_date: Some(now - Duration::hours(25)),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .histories
        .create(
            &org,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Proof),
                created_date: Some(now - Duration::hours(1)),
                ..Default::default()
            },
        )
        .await;
    // WHEN
    let resp = context
        .api
        .statistics
        .organisation_stats(Some(now - Duration::days(1)), now, org.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["current"]["verificationCount"], 1);
    assert_eq!(resp["previous"]["issuanceCount"], 1);
    assert_eq!(resp["previous"]["credentialLifecycleOperationCount"], 1);
    assert_eq!(resp["previous"]["verificationCount"], 0);
}
