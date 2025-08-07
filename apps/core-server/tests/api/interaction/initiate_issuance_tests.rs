use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;

#[tokio::test]
async fn test_initiate_issuance_endpoint() {
    let mock_server = MockServer::start().await;
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let authorization_endpoint = "https://authorization.com/authorize";
    let issuer = mock_server.uri();
    Mock::given(method(Method::GET))
        .and(path("/.well-known/oauth-authorization-server"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!(
            {
                "issuer": issuer,
                "authorization_endpoint": authorization_endpoint,
            }
        )))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .initiate_issuance(
            organisation.id,
            "OPENID4VCI_DRAFT13",
            "clientId",
            issuer,
            vec!["scope".to_string()],
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    assert!(
        resp["url"]
            .as_str()
            .unwrap()
            .starts_with(authorization_endpoint)
    );
}
