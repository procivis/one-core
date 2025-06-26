use one_core::model::history::HistoryAction;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_upsert_organisation_success_not_existing() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .upsert(&organisation_id, "name", None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let organisation = context.db.organisations.get(&organisation_id.into()).await;
    assert_eq!(organisation.name, "name");
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Created
    )
}

#[tokio::test]
async fn test_upsert_organisation_success_existing() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(&organisation.id, "name", None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(organisation.name, "name");
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    )
}

#[tokio::test]
async fn test_upsert_new_organisation_reject_duplicate_name() {
    // GIVEN
    let context = TestContext::new(None).await;
    let existing_org = context.db.organisations.create().await;

    // WHEN
    let new_org_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .upsert(&new_org_id, &existing_org.name, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_upsert_exisiting_organisation_reject_duplicate_name() {
    // GIVEN
    let context = TestContext::new(None).await;
    let existing_org = context.db.organisations.create().await;
    let existing_org2 = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(&existing_org2.id, &existing_org.name, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_upsert_organisation_with_delete() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(&organisation.id, "updated_name", Some(true))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated_organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(updated_organisation.name, "updated_name");
    assert!(updated_organisation.deactivated_at.is_some());
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}

#[tokio::test]
async fn test_upsert_organisation_reactivate_deactivated() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // Deactivate the organisation first
    context
        .api
        .organisations
        .upsert(&organisation.id, "deactivated_name", Some(true))
        .await;

    // WHEN - Reactivate the organisation
    let resp = context
        .api
        .organisations
        .upsert(&organisation.id, "reactivated_name", Some(false))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let reactivated_organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(reactivated_organisation.name, "reactivated_name");
    assert!(reactivated_organisation.deactivated_at.is_none());
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}
