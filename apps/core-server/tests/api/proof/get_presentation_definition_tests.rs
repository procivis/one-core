use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::proof::ProofStateEnum;
use serde_json::{Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::fixtures::{self, TestingCredentialParams, TestingCredentialSchemaParams};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_get_presentation_definition_openid_with_match_multiple_schemas() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;
    let identifier = fixtures::create_identifier(&db_conn, &organisation, None).await;

    let credential_schema_1 = fixtures::create_credential_schema(
        &db_conn,
        &organisation,
        Some(TestingCredentialSchemaParams {
            name: Some("schema1".to_string()),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema_2 = fixtures::create_credential_schema(
        &db_conn,
        &organisation,
        Some(TestingCredentialSchemaParams {
            name: Some("schema2".to_string()),
            ..Default::default()
        }),
    )
    .await;

    let credential1 = fixtures::create_credential(
        &db_conn,
        &credential_schema_1,
        CredentialStateEnum::Accepted,
        &identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams::default(),
    )
    .await;

    let _credential2 = fixtures::create_credential(
        &db_conn,
        &credential_schema_2,
        CredentialStateEnum::Accepted,
        &identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams::default(),
    )
    .await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(&credential_schema_1),
        &organisation,
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        &identifier,
        Some(&did),
        Some(&identifier),
        None,
        ProofStateEnum::Requested,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;
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

fn get_open_id_interaction_data(credential_schema: &CredentialSchema) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
        "client_metadata": {
            "jwks": {
                "keys": [{
                    "crv": "P-256",
                    "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }]
            },
            "vp_formats": {
                "vc+sd-jwt": {
                    "kb-jwt_alg_values": ["EdDSA", "ES256"],
                    "sd-jwt_alg_values": ["EdDSA", "ES256"]
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
        "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
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
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://localhost",
            &get_open_id_interaction_data(&credential_schema),
            &organisation,
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            Some(&did),
            Some(&identifier),
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["requestGroups"][0]["id"].assert_eq(&proof.id);
    resp["credentials"][0]["id"].assert_eq(&credential.id);
    resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"][0]
        .assert_eq(&credential.id);

    assert_eq!(
        resp["requestGroups"][0]["requestedCredentials"][0]["fields"][0]["keyMap"]
            [credential.id.to_string()]
        .as_str()
        .unwrap(),
        "firstName"
    );
}

#[tokio::test]
async fn test_get_presentation_definition_open_id_vp_with_delete_credential() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://localhost",
            &get_open_id_interaction_data(&credential_schema),
            &organisation,
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            Some(&did),
            Some(&identifier),
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["requestGroups"][0]["id"].assert_eq(&proof.id);
    assert_eq!(resp["credentials"].as_array().unwrap().len(), 0);
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
    let identifier = fixtures::create_identifier(&db_conn, &organisation, None).await;
    let credential_schema = fixtures::create_credential_schema(&db_conn, &organisation, None).await;
    let interaction = fixtures::create_interaction(
        &db_conn,
        "http://localhost",
        &get_open_id_interaction_data(&credential_schema),
        &organisation,
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        &identifier,
        Some(&did),
        Some(&identifier),
        None,
        ProofStateEnum::Requested,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;
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

fn get_open_id_interaction_data_without_vp_formats(
    credential_schema: &CredentialSchema,
) -> Vec<u8> {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
        "client_metadata": {
            "jwks": {
                "keys": [{
                    "crv": "P-256",
                    "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }]
            },
            "vp_formats": {},
            "client_id_scheme": "redirect_uri"
        },
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
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
async fn test_get_presentation_definition_open_id_vp_no_match_vp_formats_empty() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let _credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://localhost",
            &get_open_id_interaction_data_without_vp_formats(&credential_schema),
            &organisation,
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            Some(&did),
            Some(&identifier),
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert!(
        resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
            .as_array()
            .unwrap()
            .is_empty()
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
    let identifier = fixtures::create_identifier(&db_conn, &organisation, None).await;

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
        &identifier,
        "OPENID4VCI_DRAFT13",
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
        &identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams::default(),
    )
    .await;

    let interaction = fixtures::create_interaction(
        &db_conn,
        "https://core.test.one-trust-solution.com/ssi/openid4vp/draft-20/response",
        &json!({
            "response_type": "vp_token",
            "state": "30622803-c01a-4b24-9843-1aa4306510cb",
            "nonce": "5D910DcsvtdZV0VllYUjGpcpdkNtakHU",
            "client_id_scheme": "redirect_uri",
            "client_id": "https://core.test.one-trust-solution.com/ssi/openid4vp/draft-20/response",
            "client_metadata": {
                "jwks": {
                    "keys": [{
                        "crv": "P-256",
                        "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                        "kty": "EC",
                        "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                        "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                        "use": "enc"
                    }]
                },
                "vp_formats": {
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256"]
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
            "response_uri": "https://core.test.one-trust-solution.com/ssi/openid4vp/draft-20/response",
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
        &organisation,
    )
    .await;
    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        &identifier,
        Some(&did),
        Some(&identifier),
        None,
        ProofStateEnum::Requested,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;
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
                "rule": {
                    "type": "all"
                },
                "requestedCredentials": [
                    {
                        "id": "input_0",
                        "fields": [
                            {
                                "id": "109562f7-2374-4b84-ab84-67709ad25f92",
                                "name": "first.f0",
                                "required": true,
                                "keyMap": {
                                    credential_1.id.to_string(): "first.f0"
                                }
                            },
                            {
                                "id": "a85dd383-91c0-4999-9953-e857c238a4bf",
                                "name": "first_f1",
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
                        "fields": [
                            {
                                "id": "a50ff87a-fedc-4650-8b69-044bd8411f8c",
                                "name": "second_f0",
                                "required": true,
                                "keyMap": {
                                    credential_2.id.to_string(): "second_f0"
                                }
                            },
                            {
                                "id": "3fad2e18-ebb9-457a-9ed9-f818de957fdc",
                                "name": "second_f1",
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

#[tokio::test]
async fn test_get_presentation_definition_open_id_vp_matched_only_complete_credential() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let first_claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0];
    let second_claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[1];

    let incomplete_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![(
                    first_claim_schema.schema.id.into(),
                    &first_claim_schema.schema.key,
                    "value",
                )]),
                ..Default::default()
            },
        )
        .await;
    let complete_credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                claims_data: Some(vec![
                    (
                        first_claim_schema.schema.id.into(),
                        &first_claim_schema.schema.key,
                        "value",
                    ),
                    (
                        second_claim_schema.schema.id.into(),
                        &second_claim_schema.schema.key,
                        "true",
                    ),
                ]),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://localhost",
            &json!({
                "response_type": "vp_token",
                "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
                "client_id_scheme": "redirect_uri",
                "client_id": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
                "client_metadata": {
                    "jwks": {
                        "keys": [{
                            "crv": "P-256",
                            "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                            "kty": "EC",
                            "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                            "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                            "use": "enc"
                        }]
                    },
                    "vp_formats": {
                        "vc+sd-jwt": {
                            "kb-jwt_alg_values": ["EdDSA", "ES256"],
                            "sd-jwt_alg_values": ["EdDSA", "ES256"]
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
                "response_uri": "http://0.0.0.0:3000/ssi/openid4vp/draft-20/response",
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
                                        "id": first_claim_schema.schema.id,
                                        "path": [
                                            "$.vc.credentialSubject.firstName"
                                        ],
                                        "optional": false
                                    },
                                                                    {
                                        "id": second_claim_schema.schema.id,
                                        "path": [
                                            "$.vc.credentialSubject.isOver18"
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
            &organisation,
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            Some(&did),
            Some(&identifier),
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.presentation_definition(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    resp["requestGroups"][0]["id"].assert_eq(&proof.id);
    let credentials = resp["credentials"].as_array().unwrap();
    assert_eq!(2, credentials.len());

    let applicable_credentials =
        resp["requestGroups"][0]["requestedCredentials"][0]["applicableCredentials"]
            .as_array()
            .unwrap();
    assert_eq!(1, applicable_credentials.len());
    applicable_credentials[0].assert_eq(&complete_credential.id);

    let applicable_credentials =
        resp["requestGroups"][0]["requestedCredentials"][0]["inapplicableCredentials"]
            .as_array()
            .unwrap();
    assert_eq!(1, applicable_credentials.len());
    applicable_credentials[0].assert_eq(&incomplete_credential.id);
}
