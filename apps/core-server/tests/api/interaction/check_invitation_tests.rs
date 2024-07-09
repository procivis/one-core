use serde_json::json;

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_check_invitation_endpoint() {
    let context = TestContext::new().await;

    let url_openid4vc_cred_issuance = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fsomeissuer.com%2Fssi%2Foidc-issuer%2Fv1%2Ffe94cbd7-db7c-4a45-8240-efb8e6c8cd55%2Foffer%2F35e4c169-aaf8-4e9e-a01e-5b8808b2b41a";
    let response = context
        .api
        .interactions
        .check_invitation(url_openid4vc_cred_issuance)
        .await;
    assert_eq!(200, response.status());
    assert_eq!(
        json!({
            "protocol": "OPENID4VC",
            "type": "CREDENTIAL_ISSUANCE",
        }),
        response.json_value().await
    );

    let url_procivis_cred_issuance = "https://someissuer.com/ssi/temporary-issuer/v1/connect?protocol=PROCIVIS_TEMPORARY&credential=d96e571d-c265-42bf-8e02-bd6d778f7ec0";
    let response = context
        .api
        .interactions
        .check_invitation(url_procivis_cred_issuance)
        .await;
    assert_eq!(200, response.status());
    assert_eq!(
        json!({
            "protocol": "PROCIVIS_TEMPORARY",
            "type": "CREDENTIAL_ISSUANCE",
        }),
        response.json_value().await
    );

    let url_openid4vc_proof = "openid4vp://?response_type=vp_token&state=6f1d74f7-5c0a-4621-a88e-a1121956fd81&nonce=wvyL5Z6HxJ5kf8j4IEGnwAi52kwJwVKO&client_id_scheme=redirect_uri&client_id=https%3A%2F%2Fsomeissuer.com%2Fssi%2Foidc-verifier%2Fv1%2Fresponse&response_mode=direct_post&response_uri=https%3A%2F%2Fsomeissuer.com%2Fssi%2Foidc-verifier%2Fv1%2Fresponse&client_metadata_uri=https%3A%2F%2Fsomeissuer.com%2Fssi%2Foidc-verifier%2Fv1%2F922da4c6-60b0-4acd-89b5-bf2d4ff6b528%2Fclient-metadata&presentation_definition_uri=https%3A%2F%2Fsomeissuer.com%2Fssi%2Foidc-verifier%2Fv1%2F922da4c6-60b0-4acd-89b5-bf2d4ff6b528%2Fpresentation-definition";
    let response = context
        .api
        .interactions
        .check_invitation(url_openid4vc_proof)
        .await;
    assert_eq!(200, response.status());
    assert_eq!(
        json!({
            "protocol": "OPENID4VC",
            "type": "PROOF_REQUEST",
        }),
        response.json_value().await
    );

    let url_procivis_proof = "https://someissuer.com/ssi/temporary-verifier/v1/connect?protocol=PROCIVIS_TEMPORARY&proof=9d1268c4-6e76-4679-9adf-251630bb4e9c";
    let response = context
        .api
        .interactions
        .check_invitation(url_procivis_proof)
        .await;
    assert_eq!(200, response.status());
    assert_eq!(
        json!({
            "protocol": "PROCIVIS_TEMPORARY",
            "type": "PROOF_REQUEST",
        }),
        response.json_value().await
    );

    let url_invalid = "https://someissuer.com";
    let response = context.api.interactions.check_invitation(url_invalid).await;
    assert_eq!(400, response.status());
}
