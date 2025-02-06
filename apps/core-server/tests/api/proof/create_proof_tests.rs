use one_core::model::history::HistoryAction;
use one_core::model::proof::ProofStateEnum;
use serde_json::{json, Value};

use crate::fixtures::{
    self, assert_history_count, TestingConfigParams, TestingCredentialSchemaParams,
    TestingDidParams,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::db_clients::DbClient;
use crate::utils::field_match::FieldHelpers;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_create_proof_success_without_related_key() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(
            &proof_schema.id.to_string(),
            "OPENID4VC",
            &did.id.to_string(),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.exchange, "OPENID4VC");
    assert_eq!(proof.transport, "HTTP");
    assert_history_count(&context, &proof.id.into(), HistoryAction::Created, 1).await;
}

#[tokio::test]
async fn test_create_proof_success_with_related_key() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(
            &proof_schema.id.to_string(),
            "OPENID4VC",
            &did.id.to_string(),
            None,
            Some(&key.id.to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.exchange, "OPENID4VC");
}

#[tokio::test]
async fn test_create_proof_for_deactivated_did_returns_400() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            deactivated: Some(true),
            ..Default::default()
        }),
    )
    .await;

    let credential_schema = fixtures::create_credential_schema(&db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &db_conn,
        "test",
        &organisation,
        &[CreateProofInputSchema {
            claims: vec![CreateProofClaim {
                id: claim_schema.id,
                key: &claim_schema.key,
                required: true,
                data_type: &claim_schema.data_type,
                array: false,
            }],
            credential_schema: &credential_schema,
            validity_constraint: None,
        }],
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;
    let url = format!("{base_url}/api/proof-request/v1");

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "proofSchemaId": proof_schema.id,
          "exchange": "OPENID4VC",
          "verifierDid": did.id,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_create_proof_scan_to_verify_invalid_credential() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(
        &base_url,
        Some(TestingConfigParams {
            additional_config: Some(indoc::formatdoc! {"
            exchange:
                SCAN_TO_VERIFY:
                    type: \"SCAN_TO_VERIFY\"
                    display: \"exchange.scanToVerify\"
                    order: 2
            "}),
            ..Default::default()
        }),
    );
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let credential_schema = fixtures::create_credential_schema(
        &db_conn,
        &organisation,
        Some(TestingCredentialSchemaParams {
            format: Some("PHYSICAL_CARD".to_string()),
            schema_id: Some("IdentityCard".to_string()),
            ..Default::default()
        }),
    )
    .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &db_conn,
        "test",
        &organisation,
        &[CreateProofInputSchema {
            claims: vec![CreateProofClaim {
                id: claim_schema.id,
                key: &claim_schema.key,
                required: true,
                data_type: &claim_schema.data_type,
                array: false,
            }],
            credential_schema: &credential_schema,
            validity_constraint: None,
        }],
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;
    let url = format!("{base_url}/api/proof-request/v1");

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "proofSchemaId": proof_schema.id,
          "exchange": "SCAN_TO_VERIFY",
          "scanToVerify": {
            "barcode": "invalid",
            "barcodeType": "MRZ",
            "credential": "invalid"
          },
          "verifierDid": did.id,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await.unwrap();

    assert!(resp.get("id").is_some());

    let db = DbClient::new(db_conn);

    let proof = db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.exchange, "SCAN_TO_VERIFY");
    assert_eq!(proof.state, ProofStateEnum::Error);
}

#[tokio::test]
async fn test_create_proof_fail_with_operation_disabled() {
    // GIVEN
    let additional_config = Some(
        indoc::indoc! {"
        exchange:
            OPENID4VC:
                params:
                    public:
                        presentation:
                            disabled: true
    "}
        .to_string(),
    );
    let (context, organisation, did, key) = TestContext::new_with_did(additional_config).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(
            &proof_schema.id.to_string(),
            "OPENID4VC",
            &did.id.to_string(),
            None,
            Some(&key.id.to_string()),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}
