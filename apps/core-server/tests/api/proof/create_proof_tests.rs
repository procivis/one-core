use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use one_core::model::proof::ProofStateEnum;
use serde_json::{Value, json};
use similar_asserts::assert_eq;

use crate::fixtures::{
    self, TestingConfigParams, TestingCredentialSchemaParams, TestingDidParams,
    TestingIdentifierParams, assert_history_count,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::DbClient;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_create_proof_success_without_related_key() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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
            "OPENID4VP_DRAFT20",
            &did.id.to_string(),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_DRAFT20");
    assert_eq!(proof.transport, "HTTP");
    assert_history_count(&context, &proof.id.into(), HistoryAction::Created, 1).await;
}

// TODO Enable this when we reverted the other todos marked with ONE-5918
/* #[tokio::test]
async fn test_create_proof_wrong_identifier_type() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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
            "MDOC_OPENID4VP",
            &did.id.to_string(),
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0218", resp.error_code().await);
}*/

#[tokio::test]
async fn test_create_proof_success_with_related_key() {
    // GIVEN
    let (context, organisation, did, _, key) = TestContext::new_with_did(None).await;
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
            "OPENID4VP_DRAFT20",
            &did.id.to_string(),
            None,
            Some(&key.id.to_string()),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_DRAFT20");
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
    let _identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(did.clone()),
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
          "verificationProtocol": "OPENID4VP_DRAFT20",
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
            verificationProtocol:
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
          "protocol": "SCAN_TO_VERIFY",
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
    assert_eq!(proof.protocol, "SCAN_TO_VERIFY");
    assert_eq!(proof.state, ProofStateEnum::Error);
}

#[tokio::test]
async fn test_create_proof_mdoc_without_key_agreement_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key.to_owned(),
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: key.to_owned(),
                        reference: "1".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                schema_id: Some("org.iso.18013.5.1.mDL".to_string()),
                ..Default::default()
            },
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
            "OPENID4VP_DRAFT20",
            &did.id.to_string(),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0222", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_success_without_key_agreement_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: key.to_owned(),
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: key.to_owned(),
                        reference: "1".to_string(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                ..Default::default()
            },
        )
        .await;

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
            "OPENID4VP_DRAFT20",
            &did.id.to_string(),
            None,
            None,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_proof_success_with_certificate() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                ..Default::default()
            },
        )
        .await;

    let _certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            TestingCertificateParams {
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

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
        .create_with_identifier(
            &proof_schema.id.to_string(),
            "MDOC_OPENID4VP",
            &identifier.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_proof_success_with_profile() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
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

    let test_profile = "test-profile-123";

    // WHEN
    let resp = context
        .api
        .proofs
        .create(
            &proof_schema.id.to_string(),
            "OPENID4VP_DRAFT20",
            &did.id.to_string(),
            None,
            None,
            Some(test_profile),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_DRAFT20");
    assert_eq!(proof.transport, "HTTP");

    // Verify the profile is correctly stored
    assert_eq!(proof.profile.as_ref().unwrap(), test_profile);

    assert_history_count(&context, &proof.id.into(), HistoryAction::Created, 1).await;
}
