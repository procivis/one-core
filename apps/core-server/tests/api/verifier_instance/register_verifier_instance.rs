use one_core::model::history::{HistoryAction, HistoryEntityType};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::verifier_instance::TestRegisterRequest;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn register_verifier_instance_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/verifier-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "verifierName": "verifier-name",
          "featureFlags": {
            "trustEcosystemsEnabled": true
          },
          "trustCollections": []
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .register_instance(TestRegisterRequest {
            organisation_id: org.id,
            provider_url: mock_server.uri(),
            r#type: "PROCIVIS_ONE".to_string(),
        })
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let instance_id: Uuid = resp["id"].parse();

    let instance = context
        .db
        .verifier_instances
        .get(instance_id, &Default::default())
        .await
        .unwrap();
    assert_eq!(instance.provider_name, "verifier-name");
    assert_eq!(instance.provider_type, "PROCIVIS_ONE");

    let history = context
        .db
        .histories
        .get_by_entity_id(&instance_id.into())
        .await;
    assert_eq!(history.values.len(), 1);
    let event = &history.values[0];
    assert_eq!(event.action, HistoryAction::Created);
    assert_eq!(event.entity_type, HistoryEntityType::VerifierInstance);
}

#[tokio::test]
async fn register_verifier_instance_fails_when_another_one_created() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    context
        .db
        .verifier_instances
        .create(org.clone(), Default::default())
        .await;

    // when
    let resp = context
        .api
        .verifier_instances
        .register_instance(TestRegisterRequest {
            organisation_id: org.id,
            provider_url: "http://provider.url".to_string(),
            r#type: "PROCIVIS_ONE".to_string(),
        })
        .await;

    // then
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0271");
}
