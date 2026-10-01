use serde_json::json;
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_verification_protocol_capabilities() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.config.get().await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    let haip = &resp["verificationProtocol"]["OPENID4VP_FINAL1_HAIP"];
    assert_eq!(
        haip["params"]["verifier"]["supportedClientIdSchemes"],
        json!(["x509_hash"])
    );
    assert_eq!(
        haip["params"]["holder"]["supportedClientIdSchemes"],
        json!(["x509_hash"])
    );
    assert_eq!(
        haip["capabilities"]["verifierIdentifierTypes"],
        json!(["CERTIFICATE"])
    );

    let proximity = &resp["verificationProtocol"]["OPENID4VP_PROXIMITY_DRAFT00"];
    assert_eq!(
        proximity["capabilities"]["verifierIdentifierTypes"],
        json!(["CERTIFICATE", "DID"])
    );
}
