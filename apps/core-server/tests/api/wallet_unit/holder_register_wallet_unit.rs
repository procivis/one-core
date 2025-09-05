use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::api_wallet_unit_tests::create_wallet_unit_attestation;
use crate::utils::api_clients::wallet_units::TestHolderRegisterRequest;
use crate::utils::context::TestContext;

#[tokio::test]
async fn holder_register_wallet_unit_successfully() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;

    let mock_server = MockServer::builder().start().await;

    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let attestation = create_wallet_unit_attestation(
        holder_key_pair.key.public_key_as_jwk().unwrap(),
        mock_server.uri(),
    )
    .await;
    Mock::given(method(Method::POST))
        .and(path("/ssi/wallet-unit/v1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": Uuid::new_v4(),
            "attestation": attestation,
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_none());

    // when
    let resp = context
        .api
        .wallet_units
        .holder_register(TestHolderRegisterRequest {
            organization_id: Some(org.id),
            wallet_provider_url: Some(mock_server.uri()),
            key_type: Some("ECDSA".to_string()),
            ..Default::default()
        })
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let wallet_unit_attestations = context
        .db
        .wallet_unit_attestations
        .get_by_organisation(&org.id)
        .await;
    assert!(wallet_unit_attestations.is_some());
    let history = context
        .db
        .histories
        .get_by_entity_id(&wallet_unit_attestations.unwrap().id.into())
        .await;
    assert!(!history.values.is_empty());
}
