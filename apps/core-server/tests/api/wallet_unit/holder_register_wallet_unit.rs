use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::utils::api_clients::holder_wallet_unit::TestHolderRegisterRequest;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn holder_register_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    Mock::given(method(Method::GET))
        .and(path("/ssi/wallet-provider/v1/PROCIVIS_ONE"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
          "name": "PROCIVIS_ONE",
          "walletUnitAttestation": {
            "appIntegrityCheckRequired": false,
            "enabled": true,
            "required": true
          }
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    // when
    let resp = context
        .api
        .holder_wallet_units
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(format!(
                "{}/ssi/wallet-provider/v1/PROCIVIS_ONE",
                mock_server.uri()
            )),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // then
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let history = context
        .db
        .histories
        .get_by_entity_id(&resp["id"].parse())
        .await;
    assert!(!history.values.is_empty());
}
