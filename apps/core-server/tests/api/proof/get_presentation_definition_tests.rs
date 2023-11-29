use core_server::router::start_server;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::proof::ProofStateEnum;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{fixtures, utils};

#[tokio::test]
async fn test_get_presentation_definition_procivis_temporary_with_match() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Created,
        &did,
        None,
        "PROCIVIS_TEMPORARY",
    )
    .await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_procivis_temporary_interaction_data(
            "firstName".to_string(),
            credential_schema.id.to_string(),
        ),
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        Some(&did),
        None,
        ProofStateEnum::Pending,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(
        resp["requestGroups"][0]["id"].as_str().unwrap(),
        proof.id.to_string()
    );
    assert_eq!(
        resp["credentials"][0]["id"].as_str().unwrap(),
        credential.id.to_string()
    );
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"][0]
            .as_str()
            .unwrap(),
        credential.id.to_string()
    );
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["keyMap"]
            [credential.id.to_string()]
        .as_str()
        .unwrap(),
        "firstName".to_string()
    );
}

#[tokio::test]
async fn test_get_presentation_definition_procivis_temporary_no_match() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_procivis_temporary_interaction_data(
            "test".to_string(),
            credential_schema.id.to_string(),
        ),
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        Some(&did),
        None,
        ProofStateEnum::Pending,
        "PROCIVIS_TEMPORARY",
        Some(&interaction),
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(
        resp["requestGroups"][0]["id"].as_str().unwrap(),
        proof.id.to_string()
    );
    assert_eq!(resp["credentials"].as_array().unwrap().len(), 0);
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let first_applicable_credential = resp["requestGroups"][0]["requestedCredentials"][0].clone();

    assert_eq!(
        first_applicable_credential["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        first_applicable_credential["id"].as_str().unwrap(),
        "input_0".to_string()
    );
    assert_eq!(
        first_applicable_credential["fields"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

fn get_procivis_temporary_interaction_data(key: String, credential_schema: String) -> Vec<u8> {
    json!([{
        "id": Uuid::new_v4().to_string(),
        "createdDate": "2023-06-09T14:19:57.000Z",
        "lastModified": "2023-06-09T14:19:57.000Z",
        "key": key,
        "datatype": "STRING",
        "required": true,
        "credentialSchema": {
             "id": credential_schema,
             "createdDate": "2023-06-09T14:19:57.000Z",
             "lastModified": "2023-06-09T14:19:57.000Z",
             "name": "test",
             "format": "JWT",
             "revocationMethod": "NONE",
        }
    }])
    .to_string()
    .into_bytes()
}

fn get_open_id_interaction_data() -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/oidc-verifier/v1/response",
        "client_metadata": {
            "vp_formats": {
                "vc+sd-jwt": {
                    "alg": [
                        "EdDSA"
                    ]
                },
                "jwt_vp_json": {
                    "alg": [
                        "EdDSA"
                    ]
                },
                "jwt_vc_json": {
                    "alg": [
                        "EdDSA"
                    ]
                }
            },
            "client_id_scheme": "redirect_uri"
        },
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/oidc-verifier/v1/response",
        "presentation_definition": {
            "id": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
            "input_descriptors": [
                {
                    "id": "input_0",
                    "constraints": {
                        "fields": [
                            {
                                "id": "2c99eaf6-1b23-4554-afb5-464f92103bf3",
                                "path": [
                                    "$.vc.credentialSubject.firstName"
                                ],
                                "optional": false
                            }
                        ]
                    }
                }
            ]
        }
    })
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn test_get_presentation_definition_open_id_vp_with_match() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Created,
        &did,
        None,
        "OPENID4VC",
    )
    .await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(),
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        Some(&did),
        None,
        ProofStateEnum::Pending,
        "OPENID4VC",
        Some(&interaction),
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN

    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(
        resp["requestGroups"][0]["id"].as_str().unwrap(),
        proof.id.to_string()
    );
    assert_eq!(
        resp["credentials"][0]["id"].as_str().unwrap(),
        credential.id.to_string()
    );
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"][0]
            .as_str()
            .unwrap(),
        credential.id.to_string()
    );
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["keyMap"]
            [credential.id.to_string()]
        .as_str()
        .unwrap(),
        "firstName".to_string()
    );
}

#[tokio::test]
async fn test_get_presentation_definition_open_id_vp_no_match() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did_key(&db_conn, &organisation).await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(),
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        Some(&did),
        None,
        ProofStateEnum::Pending,
        "OPENID4VC",
        Some(&interaction),
    )
    .await;

    // WHEN
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let _handle = tokio::spawn(async move { start_server(listener, config, db_conn).await });

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(
        resp["requestGroups"][0]["id"].as_str().unwrap(),
        proof.id.to_string()
    );
    assert_eq!(resp["credentials"].as_array().unwrap().len(), 0);
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let first_applicable_credential = resp["requestGroups"][0]["requestedCredentials"][0].clone();

    assert_eq!(
        first_applicable_credential["applicableCredentials"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        first_applicable_credential["id"].as_str().unwrap(),
        "input_0".to_string()
    );
    assert_eq!(
        first_applicable_credential["fields"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}
