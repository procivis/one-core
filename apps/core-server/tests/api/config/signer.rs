use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_signer_config_exposes_max_validity_duration() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["signer"]["REGISTRATION_CERTIFICATE"]["params"]["maxValidityDurationSeconds"],
        2592000
    );
    assert_eq!(
        resp["signer"]["ACCESS_CERTIFICATE"]["params"]["maxValidityDurationSeconds"],
        157680000
    );
    assert_eq!(
        resp["signer"]["X509_CERTIFICATE"]["params"]["maxValidityDurationSeconds"],
        157680000
    );

    // private params must stay hidden
    assert_eq!(
        resp["signer"]["REGISTRATION_CERTIFICATE"]["params"]["payload"],
        serde_json::Value::Null
    );
    assert_eq!(
        resp["signer"]["REGISTRATION_CERTIFICATE"]["params"]["revocationMethod"],
        serde_json::Value::Null
    );
    assert_eq!(
        resp["signer"]["ACCESS_CERTIFICATE"]["params"]["revocationMethod"],
        serde_json::Value::Null
    );
    assert_eq!(
        resp["signer"]["X509_CERTIFICATE"]["params"]["payload"],
        serde_json::Value::Null
    );
    assert_eq!(
        resp["signer"]["X509_CERTIFICATE"]["params"]["revocationMethod"],
        serde_json::Value::Null
    );
}

#[tokio::test]
async fn test_signer_config_max_validity_duration_reflects_override() {
    // GIVEN
    let config = indoc::indoc! {"
      signer:
        REGISTRATION_CERTIFICATE:
          params:
            public:
              maxValidityDurationSeconds: 604800
        X509_CERTIFICATE:
          params:
            public:
              maxValidityDurationSeconds: 604800
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(
        resp["signer"]["REGISTRATION_CERTIFICATE"]["params"]["maxValidityDurationSeconds"],
        604800
    );
    assert_eq!(
        resp["signer"]["X509_CERTIFICATE"]["params"]["maxValidityDurationSeconds"],
        604800
    );
}
