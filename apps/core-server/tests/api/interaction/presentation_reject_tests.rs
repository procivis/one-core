use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use wiremock::{
    http::Method,
    matchers::{method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use crate::{
    fixtures,
    utils::{self, server::run_server},
};

#[tokio::test]
async fn test_presentation_reject_endpoint_for_procivis_temp() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let holder_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let verifier_url = mock_server.uri();

    let interaction = fixtures::create_interaction(&db_conn, &verifier_url, "".as_bytes()).await;

    let proof = fixtures::create_proof(
        &db_conn,
        &verifier_did,
        Some(&holder_did),
        None,
        ProofStateEnum::Pending,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/temporary-verifier/v1/reject"))
        .and(query_param("proof", proof.id.to_string()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let _handle = run_server(listener, config, &db_conn);

    let url = format!("{base_url}/api/interaction/v1/presentation-reject");

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert!(proof
        .state
        .as_ref()
        .unwrap()
        .iter()
        .any(|p| p.state == ProofStateEnum::Rejected));
}
