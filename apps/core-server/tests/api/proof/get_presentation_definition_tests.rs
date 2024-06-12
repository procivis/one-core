use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::proof::ProofStateEnum;
use one_core::model::{credential::CredentialStateEnum, credential_schema::CredentialSchema};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::fixtures::TestingDidParams;
use crate::utils::server::run_server;
use crate::{
    fixtures::{self, TestingCredentialParams},
    utils,
};

fn get_procivis_temporary_interaction_data(
    key: String,
    credential_schema: &CredentialSchema,
) -> Vec<u8> {
    json!([{
        "id": Uuid::new_v4().to_string(),
        "createdDate": "2023-06-09T14:19:57.000Z",
        "lastModified": "2023-06-09T14:19:57.000Z",
        "key": key,
        "datatype": "STRING",
        "required": true,
        "credentialSchema": {
             "id": credential_schema.id,
             "createdDate": "2023-06-09T14:19:57.000Z",
             "lastModified": "2023-06-09T14:19:57.000Z",
             "name": "test",
             "format": "JWT",
             "revocationMethod": "NONE",
             "schemaType": "ProcivisOneSchema2024",
             "schemaId": credential_schema.schema_id,
        }
    }])
    .to_string()
    .into_bytes()
}

#[tokio::test]
async fn test_get_presentation_definition_procivis_temporary_with_match() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_procivis_temporary_interaction_data("firstName".to_string(), &credential_schema),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

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
    assert!(resp["credentials"][0]["role"].is_string());
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
async fn test_get_presentation_definition_procivis_temporary_with_match_multiple_schemas() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema_1 =
        fixtures::create_credential_schema(&db_conn, "schema1", &organisation, "NONE").await;
    let credential_schema_2 =
        fixtures::create_credential_schema(&db_conn, "schema2", &organisation, "NONE").await;

    let credential1 = fixtures::create_credential(
        &db_conn,
        &credential_schema_1,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let _credential2 = fixtures::create_credential(
        &db_conn,
        &credential_schema_2,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_procivis_temporary_interaction_data("firstName".to_string(), &credential_schema_1),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(resp["credentials"].as_array().unwrap().len(), 1);
    assert_eq!(
        resp["requestGroups"][0]["id"].as_str().unwrap(),
        proof.id.to_string()
    );
    assert_eq!(
        resp["credentials"][0]["id"].as_str().unwrap(),
        credential1.id.to_string()
    );
    assert!(resp["credentials"][0]["role"].is_string());
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"][0]
            .as_str()
            .unwrap(),
        credential1.id.to_string()
    );
    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["keyMap"]
            [credential1.id.to_string()]
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
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_procivis_temporary_interaction_data("test".to_string(), &credential_schema),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

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

#[tokio::test]
async fn test_get_presentation_definition_procivis_temporary_multiple_credentials() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let claim_schemas_1: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "first_f0", true, "STRING", false),
        (Uuid::new_v4(), "first_f1", false, "STRING", false),
    ];
    let credential_schema_1 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "test1",
        &organisation,
        "NONE",
        &claim_schemas_1,
    )
    .await;
    let credential_1 = fixtures::create_credential(
        &db_conn,
        &credential_schema_1,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let claim_schemas_2: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "second_f0", true, "STRING", false),
        (Uuid::new_v4(), "second_f1", false, "STRING", false),
    ];
    let credential_schema_2 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "test2",
        &organisation,
        "NONE",
        &claim_schemas_2,
    )
    .await;
    let credential_2 = fixtures::create_credential(
        &db_conn,
        &credential_schema_2,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &json!([{
            "id": "839915f5-e4e2-4591-9d80-fd6178aa84f5",
            "createdDate": "2023-06-09T14:19:57.000Z",
            "lastModified": "2023-06-09T14:19:57.000Z",
            "key": "first_f0",
            "datatype": "STRING",
            "required": true,
            "credentialSchema": {
                 "id": credential_schema_1.id,
                 "createdDate": "2023-06-09T14:19:57.000Z",
                 "lastModified": "2023-06-09T14:19:57.000Z",
                 "name": "test",
                 "format": "JWT",
                 "revocationMethod": "NONE",
                 "schemaType": "ProcivisOneSchema2024",
                 "schemaId": credential_schema_1.id,
            }
        },
        {
            "id": "ba2c4567-7c5b-4ee5-b3d6-6eac9161892e",
            "createdDate": "2023-06-09T14:19:57.000Z",
            "lastModified": "2023-06-09T14:19:57.000Z",
            "key": "second_f0",
            "datatype": "STRING",
            "required": true,
            "credentialSchema": {
                 "id": credential_schema_2.id,
                 "createdDate": "2023-06-09T14:19:57.000Z",
                 "lastModified": "2023-06-09T14:19:57.000Z",
                 "name": "test",
                 "format": "JWT",
                 "revocationMethod": "NONE",
                 "schemaType": "ProcivisOneSchema2024",
                 "schemaId": credential_schema_2.id,
            }
        }])
        .to_string()
        .into_bytes(),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(resp["credentials"].as_array().unwrap().len(), 2);
    assert_eq!(
        resp["requestGroups"],
        json!([
            {
                "id": proof.id,
                "name": null,
                "purpose": null,
                "rule": {
                    "type": "all",
                    "count": null,
                    "max": null,
                    "min": null
                },
                "requestedCredentials": [
                    {
                        "id": "input_0",
                        "name": null,
                        "purpose": null,
                        "validityCredentialNbf": null,
                        "fields": [
                            {
                                "id": "839915f5-e4e2-4591-9d80-fd6178aa84f5",
                                "name": "first_f0",
                                "purpose": null,
                                "required": true,
                                "keyMap": {
                                    credential_1.id.to_string(): "first_f0"
                                }
                            }
                        ],
                        "applicableCredentials": [credential_1.id]
                    },
                    {
                        "id": "input_1",
                        "name": null,
                        "purpose": null,
                        "validityCredentialNbf": null,
                        "fields": [
                            {
                                "id": "ba2c4567-7c5b-4ee5-b3d6-6eac9161892e",
                                "name": "second_f0",
                                "purpose": null,
                                "required": true,
                                "keyMap": {
                                    credential_2.id.to_string(): "second_f0"
                                }
                            }
                        ],
                        "applicableCredentials": [credential_2.id]
                    }
                ]
            }
        ])
    );
}

fn get_open_id_interaction_data(credential_schema: &CredentialSchema) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/oidc-verifier/v1/response",
        "client_metadata": {
            "jwks": [
                {
                    "crv": "P-256",
                    "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }
            ],
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
                },
                "mso_mdoc": {
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
                    "format": {
                        "jwt_vc_json": {
                            "alg": ["EdDSA", "ES256"]
                        }
                    },
                    "id": "input_0",
                    "constraints": {
                        "fields": [
                            {
                                "path":["$.credentialSchema.id"],
                                "filter": {
                                    "type": "string",
                                    "const": credential_schema.schema_id
                                }
                            },
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
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let key = fixtures::create_key(&db_conn, &organisation, None).await;
    let did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::KeyAgreement,
                key,
            }]),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(&credential_schema),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

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
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(&credential_schema),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

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

#[tokio::test]
async fn test_get_presentation_definition_open_id_vp_multiple_credentials() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let claim_schemas_1: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "first.f0", true, "STRING", false),
        (Uuid::new_v4(), "first_f1", false, "STRING", false),
    ];
    let credential_schema_1 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "test1",
        &organisation,
        "NONE",
        &claim_schemas_1,
    )
    .await;
    let credential_1 = fixtures::create_credential(
        &db_conn,
        &credential_schema_1,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let claim_schemas_2: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "second_f0", true, "STRING", false),
        (Uuid::new_v4(), "second_f1", false, "STRING", false),
    ];
    let credential_schema_2 = fixtures::create_credential_schema_with_claims(
        &db_conn,
        "test2",
        &organisation,
        "NONE",
        &claim_schemas_2,
    )
    .await;
    let credential_2 = fixtures::create_credential(
        &db_conn,
        &credential_schema_2,
        CredentialStateEnum::Accepted,
        &did,
        "PROCIVIS_TEMPORARY",
        TestingCredentialParams::default(),
    )
    .await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "https://core.test.one-trust-solution.com/ssi/oidc-verifier/v1/response",
        &json!({
            "response_type": "vp_token",
            "state": "30622803-c01a-4b24-9843-1aa4306510cb",
            "nonce": "5D910DcsvtdZV0VllYUjGpcpdkNtakHU",
            "client_id_scheme": "redirect_uri",
            "client_id": "https://core.test.one-trust-solution.com/ssi/oidc-verifier/v1/response",
            "client_metadata": {
                "jwks": [
                    {
                        "crv": "P-256",
                        "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                        "kty": "EC",
                        "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                        "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                        "use": "enc"
                    }
                ],
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
                    },
                    "mso_mdoc": {
                        "alg": [
                            "EdDSA"
                        ]
                    }
                },
                "client_id_scheme": "redirect_uri"
            },
            "response_mode": "direct_post",
            "response_uri": "https://core.test.one-trust-solution.com/ssi/oidc-verifier/v1/response",
            "presentation_definition": {
                "id": "30622803-c01a-4b24-9843-1aa4306510cb",
                "input_descriptors": [
                    {
                        "format": {
                            "jwt_vc_json": {
                                "alg": ["EdDSA", "ES256"]
                            }
                        },
                        "id": "input_0",
                        "constraints": {
                            "fields": [
                                {
                                    "path":["$.credentialSchema.id"],
                                    "filter": {
                                        "type": "string",
                                        "const": credential_schema_1.schema_id
                                    }
                                },
                                {
                                    "id": "109562f7-2374-4b84-ab84-67709ad25f92",
                                    "path": [
                                        "$.vc.credentialSubject.first.f0"
                                    ],
                                    "optional": false
                                },
                                {
                                    "id": "a85dd383-91c0-4999-9953-e857c238a4bf",
                                    "path": [
                                        "$.vc.credentialSubject.first_f1"
                                    ],
                                    "optional": true
                                }
                            ]
                        }
                    },
                    {
                        "format": {
                            "jwt_vc_json": {
                                "alg": ["EdDSA", "ES256"]
                            }
                        },
                        "id": "input_1",
                        "constraints": {
                            "fields": [
                                {
                                    "path":["$.credentialSchema.id"],
                                    "filter": {
                                        "type": "string",
                                        "const": credential_schema_2.schema_id
                                    }
                                },
                                {
                                    "id": "a50ff87a-fedc-4650-8b69-044bd8411f8c",
                                    "path": [
                                        "$.vc.credentialSubject.second_f0"
                                    ],
                                    "optional": false
                                },
                                {
                                    "id": "3fad2e18-ebb9-457a-9ed9-f818de957fdc",
                                    "path": [
                                        "$.vc.credentialSubject.second_f1"
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
        .into_bytes(),
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
    let _handle = run_server(listener, config, &db_conn);
    let url = format!(
        "{base_url}/api/proof-request/v1/{}/presentation-definition",
        proof.id
    );

    let resp = utils::client()
        .get(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN

    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();

    assert_eq!(resp["credentials"].as_array().unwrap().len(), 2);
    assert_eq!(
        resp["requestGroups"],
        json!([
            {
                "id": proof.id,
                "name": null,
                "purpose": null,
                "rule": {
                    "type": "all",
                    "count": null,
                    "max": null,
                    "min": null
                },
                "requestedCredentials": [
                    {
                        "id": "input_0",
                        "name": null,
                        "purpose": null,
                        "validityCredentialNbf": null,
                        "fields": [
                            {
                                "id": "109562f7-2374-4b84-ab84-67709ad25f92",
                                "name": "first.f0",
                                "purpose": null,
                                "required": true,
                                "keyMap": {
                                    credential_1.id.to_string(): "first.f0"
                                }
                            },
                            {
                                "id": "a85dd383-91c0-4999-9953-e857c238a4bf",
                                "name": "first_f1",
                                "purpose": null,
                                "required": false,
                                "keyMap": {
                                    credential_1.id.to_string(): "first_f1"
                                }
                            }
                        ],
                        "applicableCredentials": [credential_1.id]
                    },
                    {
                        "id": "input_1",
                        "name": null,
                        "purpose": null,
                        "validityCredentialNbf": null,
                        "fields": [
                            {
                                "id": "a50ff87a-fedc-4650-8b69-044bd8411f8c",
                                "name": "second_f0",
                                "purpose": null,
                                "required": true,
                                "keyMap": {
                                    credential_2.id.to_string(): "second_f0"
                                }
                            },
                            {
                                "id": "3fad2e18-ebb9-457a-9ed9-f818de957fdc",
                                "name": "second_f1",
                                "purpose": null,
                                "required": true,
                                "keyMap": {
                                    credential_2.id.to_string(): "second_f1"
                                }
                            }
                        ],
                        "applicableCredentials": [credential_2.id]
                    }
                ]
            }
        ])
    );
}
