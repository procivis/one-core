use crate::fixtures::TestingDidParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_did_list_filters_deactivated_dids() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    let expected_did = context
        .db
        .dids
        .create(
            &organisation,
            TestingDidParams {
                deactivated: Some(false),
                ..Default::default()
            },
        )
        .await;
    context
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
    let resp = context.api.dids.list(0, 10, &organisation.id, false).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
    values[0]["id"].assert_eq(&expected_did.id);
}
