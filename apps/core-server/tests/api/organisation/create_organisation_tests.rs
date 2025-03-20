use one_core::model::history::HistoryAction;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_organisation_success_id_set() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .create(Some(organisation_id), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    resp.json_value().await["id"].assert_eq(&organisation_id);
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation_id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Created
    )
}

#[tokio::test]
async fn test_create_organisation_success_name_set() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.organisations.create(None, Some("name")).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse();
    let org = context.db.organisations.get(&id).await;
    assert_eq!(org.name, "name");
}

#[tokio::test]
async fn test_create_organisation_success_id_not_set() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.organisations.create(None, None).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse();
    context.db.organisations.get(&id).await;
}

#[tokio::test]
async fn test_create_organisation_reject_duplicate_id() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation_id = Uuid::new_v4();

    // WHEN
    let resp = context
        .api
        .organisations
        .create(Some(organisation_id), None)
        .await;
    let resp2 = context
        .api
        .organisations
        .create(Some(organisation_id), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp2.status(), 400);
    assert_eq!(resp2.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_create_organisation_reject_duplicate_name() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.organisations.create(None, Some("name")).await;
    let resp2 = context.api.organisations.create(None, Some("name")).await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp2.status(), 400);
    assert_eq!(resp2.error_code().await, "BR_0023");
}
