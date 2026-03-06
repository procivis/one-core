use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_get_verifier_provider_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_verifier_provider("PROCIVIS_ONE").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["verifierName"], "Procivis One Verifier");
    assert_eq!(body["appVersion"]["minimum"], "v1.50.0");
    assert_eq!(body["appVersion"]["minimumRecommended"], "v1.55.0");

    let reject = body["appVersion"]["reject"].as_array().unwrap();
    assert_eq!(reject.len(), 1);
    assert_eq!(reject[0], "v1.51.0");

    assert_eq!(
        body["appVersion"]["updateScreen"]["link"],
        "https//example.com"
    );
}

#[tokio::test]
async fn test_get_verifier_provider_failure() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_verifier_provider("DOES_NOT_EXIST")
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
