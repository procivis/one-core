use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_update_remote_trust_entity_success() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    Mock::given(method(Method::PATCH))
        .and(path(format!("/ssi/trust-entity/v1/{}", did.did)))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&mock_server)
        .await;

    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name".to_string(),
            publisher_reference: format!("{}/ssi/trust/v1/{}", mock_server.uri(), Uuid::new_v4()),
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update_remote(
            &did,
            PatchTrustEntityRequestRestDTO {
                action: None,
                name: Some("new_name".to_string()),
                logo: Some(None),
                website: Some(Some("new_website".to_string())),
                terms_url: None,
                privacy_url: None,
                role: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn test_update_remote_trust_entity_invalid_action() {
    // GIVEN
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            name: "name".to_string(),
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update_remote(
            &did,
            PatchTrustEntityRequestRestDTO {
                action: Some(PatchTrustEntityActionRestDTO::Remove),
                name: None,
                logo: None,
                website: None,
                terms_url: None,
                privacy_url: None,
                role: None,
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0181", resp.error_code().await);
}
