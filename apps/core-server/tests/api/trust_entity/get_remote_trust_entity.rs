use serde_json::json;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_remote_trust_entity_success() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let (context, _, did, _) = TestContext::new_with_did(None).await;

    let trust_entity_id = Uuid::new_v4();
    let org_id = Uuid::new_v4();
    let publisher_reference = format!("{}/ssi/trust/v1/{}", mock_server.uri(), Uuid::new_v4());
    Mock::given(method(Method::GET))
        .and(path(format!("/ssi/trust-entity/v1/{}", did.did)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": trust_entity_id,
            "organisationId": org_id,
            "createdDate": "2023-06-09T14:19:57.000Z",
            "lastModified": "2023-06-09T14:19:57.000Z",
            "name": "Name",
            "role": "ISSUER",
            "state": "ACTIVE",
            "termsUrl": "Terms URL",
            "did": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "createdDate": "2023-06-09T14:19:57.000Z",
                "lastModified": "2023-06-09T14:19:57.000Z",
                "deactivated": false,
                "did": did.did,
                "method": did.did_method,
                "name": did.name,
                "type": "REMOTE"
            },
            "trustAnchor": {
                "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
                "createdDate": "2023-06-09T14:19:57.000Z",
                "lastModified": "2023-06-09T14:19:57.000Z",
                "isPublisher": true,
                "name": "string",
                "publisherReference": publisher_reference,
                "type": "string"
            }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            publisher_reference,
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context.api.trust_entities.get_remote(&did).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;
    body["id"].assert_eq(&trust_entity_id);
    assert_eq!(body["role"], "ISSUER");
    assert_eq!(body["state"], "ACTIVE");
    assert_eq!(body["termsUrl"], "Terms URL");
    body["did"]["did"].assert_eq(&did.did);
    body["organisationId"].assert_eq(&org_id);
}
