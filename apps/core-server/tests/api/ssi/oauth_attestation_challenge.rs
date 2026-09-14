use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_oauth_attestation_challenge() {
    // GIVEN
    let config = indoc::indoc! {"
      issuanceProtocol:
        OPENID4VCI_FINAL1:
          params:
            private:
              oauthAttestationChallenge:
                signingKey: \"93d9182795f0d1bec61329fc2d18c4b4c1b7e65e69e20ec30a2101a9875fff7e\"
    "}
    .to_string();
    let context = TestContext::new(Some(config)).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .generate_oauth_attestation_challenge("OPENID4VCI_FINAL1")
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;

    assert!(body["attestation_challenge"].is_string());
}
