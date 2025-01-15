use crate::fixtures::TestingDidParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_did_ok() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.dids.get(&did.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    resp["id"].assert_eq(&did.id);
    assert!(resp["deactivated"].as_bool().unwrap());
}
