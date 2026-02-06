use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_wallet_provider_metadata_success() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": true,
                "enabled": true,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0"
            }
        })
    );
}

#[tokio::test]
async fn test_wallet_provider_metadata_success_all_fields() {
    // GIVEN
    let config = indoc::indoc! {"
      walletProvider:
        PROCIVIS_ONE:
          params:
            public:
              walletRegistration: DISABLED
              walletInstanceAttestation:
                integrityCheck:
                  enabled: false
              appVersion:
                minimum: v1.50.0
                minimumRecommended: v.1.20.0
                reject:
                    - v1.10.0
                    - v1.11.0
                updateScreen:
                  link: https://example.com
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": false,
                "enabled": false,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0",
                "minimumRecommended": "v.1.20.0",
                "reject": ["v1.10.0", "v1.11.0"],
                "updateScreen": {
                    "link": "https://example.com"
                }
            }
        })
    );
}

#[tokio::test]
async fn test_wallet_provider_metadata_fails_disabled_wallet_provider() {
    // GIVEN
    let config = indoc::indoc! {"
      app:
        enableWalletProvider: false
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("PROCIVIS_ONE")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp,
        serde_json::json!({
            "walletUnitAttestation": {
                "appIntegrityCheckRequired": true,
                "enabled": true,
                "required": false
            },
            "name":"PROCIVIS_ONE",
            "appVersion": {
                "minimum":"v1.50.0"
            }
        })
    );
}

#[tokio::test]
async fn test_wallet_provider_metadata_fails_unknown_wallet_provider() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_wallet_provider_metadata("UNKNOWN_WALLET_PROVIDER")
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
