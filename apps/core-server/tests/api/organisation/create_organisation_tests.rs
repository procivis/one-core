use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_organisation_success_id_set() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .create(Some(organisation_id))
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    resp.json_value().await["id"].assert_eq(&organisation_id);
}

#[tokio::test]
async fn test_create_organisation_success_id_not_set() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.organisations.create(None).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse();
    context.db.organisations.get(&id).await;
}
