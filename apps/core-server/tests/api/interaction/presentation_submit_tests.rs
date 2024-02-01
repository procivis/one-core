use core_server::router::start_server;
use one_core::model::{
    credential::CredentialStateEnum,
    did::{KeyRole, RelatedKey},
    proof::ProofStateEnum,
};
use serde_json::json;
use wiremock::{
    http::Method::Post,
    matchers::{body_string_contains, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use crate::{
    fixtures::{self, TestingCredentialParams, TestingDidParams, TestingKeyParams},
    utils,
};

#[tokio::test]
async fn test_presentation_submit_endpoint_for_procivis_temp() {
    // GIVEN
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let issuer_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let key = fixtures::create_eddsa_key(&db_conn, &organisation).await;
    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key,
            }]),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "Schema1", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &issuer_did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams {
            holder_did: Some(holder_did.clone()),
            credential: Some("TOKEN"),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = mock_server.uri();
    let claims = credential.claims.clone().unwrap();

    let interaction = fixtures::create_interaction(
        &db_conn,
        &verifier_url,
        json!(
            [
                {
                    "id": claims.first().unwrap().id.clone(),
                    "createdDate": "2023-11-15T11:59:13.924Z",
                    "lastModified": "2023-11-15T11:59:13.924Z",
                    "key": "firstName",
                    "datatype": "STRING",
                    "required": true,
                    "credentialSchema": {
                        "id": credential_schema.id,
                        "createdDate": "2023-11-15T11:59:13.924Z",
                        "lastModified": "2023-11-15T11:59:13.924Z",
                        "name": "Schema1",
                        "format": "JWT",
                        "revocationMethod": "NONE"
                    }
                }
            ]
        )
        .to_string()
        .as_bytes(),
    )
    .await;

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

    Mock::given(method(Post))
        .and(path("/ssi/temporary-verifier/v1/submit"))
        .and(query_param("proof", proof.id.to_string()))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let url = format!("{base_url}/api/interaction/v1/presentation-submit");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": [
                credential.claims.unwrap().first().unwrap().id
              ]
            }
          }
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
        .any(|p| p.state == ProofStateEnum::Accepted));
    assert!(proof
        .claims
        .as_ref()
        .unwrap()
        .iter()
        .any(|c| c.claim.value == "test"));
    assert_eq!(proof.verifier_did.unwrap().did, verifier_did.did);
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vc() {
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let issuer_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;

    let holder_key = fixtures::create_key(
        &db_conn,
        &organisation,
        Some(TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".to_string()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key,
            }]),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "Schema1", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &issuer_did,
        "OPENID4VC",
        TestingCredentialParams {
            holder_did: Some(holder_did.clone()),
            credential: Some("TOKEN"),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = mock_server.uri();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let claims = credential.claims.clone().unwrap();
    let interaction = fixtures::create_interaction(
        &db_conn,
        &verifier_url,
        json!(
            {
                "response_type":"vp_token",
                "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
                "nonce":"QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
                "client_id_scheme":"redirect_uri",
                "client_id": format!("{verifier_url}/ssi/oidc-verifier/v1/response"),
                "client_metadata":
                {
                    "vp_formats":
                    {
                        "jwt_vp_json":
                        {
                            "alg":["EdDSA"]
                        },
                        "jwt_vc_json":{
                            "alg":["EdDSA"]
                        },
                        "ldp_vp":{
                            "alg":["EdDSA"]
                        },
                        "ldp_vc":{
                            "alg":["EdDSA"]
                        },
                        "vc+sd-jwt":{
                            "alg":["EdDSA"]
                        }
                    },
                    "client_id_scheme":"redirect_uri"
                },
                "response_mode":"direct_post",
                "response_uri": format!("{verifier_url}/ssi/oidc-verifier/v1/response"),
                "presentation_definition":
                {
                    "id":"fa42f6f7-f1a7-4af6-aa0e-970468cc4b3f",
                    "input_descriptors":
                    [
                        {
                            "id":"input_0",
                            "constraints":{
                                "fields":[
                                    {
                                        "id": claims[0].id,
                                        "path":["$.vc.credentialSubject.firstName"],
                                        "optional":false
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        )
        .to_string()
        .as_bytes(),
    )
    .await;

    let proof = fixtures::create_proof(
        &db_conn,
        &verifier_did,
        Some(&holder_did),
        None,
        ProofStateEnum::Pending,
        "OPENID4VC",
        Some(&interaction),
    )
    .await;

    Mock::given(method(Post))
        .and(path("/ssi/oidc-verifier/v1/response".to_owned()))
        // Just sample query params as they are too dynamic and contain random ids
        .and(body_string_contains("state"))
        .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f"))
        .and(body_string_contains("vp_token"))
        .and(body_string_contains("descriptor_map"))
        .and(body_string_contains("input_0"))
        .and(body_string_contains("jwt_vp_json")) // As we use jwt as credential input. Temporary.
        .and(body_string_contains("verifiableCredential"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let url = format!("{base_url}/api/interaction/v1/presentation-submit");

    let db_conn_clone = db_conn.clone();
    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn_clone).await });

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": [
                credential.claims.unwrap().first().unwrap().id
              ]
            }
          }
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
        .any(|p| p.state == ProofStateEnum::Accepted));
    assert!(proof
        .claims
        .as_ref()
        .unwrap()
        .iter()
        .any(|c| c.claim.value == "test"));
    assert_eq!(proof.verifier_did.unwrap().did, verifier_did.did);
}
