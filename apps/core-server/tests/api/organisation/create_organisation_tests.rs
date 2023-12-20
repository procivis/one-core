use crate::utils::{context::TestContext, field_match::FieldHelpers};
use uuid::Uuid;

#[tokio::test]
async fn test_create_organisation_success_id_set() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api_client
        .create_organisation(Some(organisation_id))
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
    let resp = context.api_client.create_organisation(None).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse();
    context.db.get_organisation(id).await;
}
