use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_wallet_provider_enabled_true() {
    // GIVEN
    let additional_config = Some(
        indoc::indoc! {"
            app:
                enableWalletProvider: true
        "}
        .to_string(),
    );
    let context = TestContext::new(additional_config).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["frontend"]["walletProviderEnabled"], json!(true));
}

#[tokio::test]
async fn test_wallet_provider_enabled_false() {
    // GIVEN
    let additional_config = Some(
        indoc::indoc! {"
            app:
                enableWalletProvider: false
        "}
        .to_string(),
    );
    let context = TestContext::new(additional_config).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["frontend"]["walletProviderEnabled"], json!(false));
}
