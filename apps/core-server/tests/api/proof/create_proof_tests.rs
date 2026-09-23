use std::str::FromStr;

use one_core::model::certificate::CertificateRole;
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::did::{Did, KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::IdentifierType;
use one_core::model::organisation::Organisation;
use one_core::model::proof_schema::ProofSchema;
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{self, TestingDidParams, TestingIdentifierParams, assert_history_count};
use crate::utils;
use crate::utils::api_clients::proofs::CreateProofTestParams;
use crate::utils::context::TestContext;
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
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_FINAL1");
    assert_eq!(proof.transport, "HTTP");
    assert_history_count(&context, &proof.id.into(), HistoryAction::Created, 1).await;
}

#[tokio::test]
async fn test_create_proof_wrong_identifier_type() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1_HAIP".into(),
            verifier_did: did.id.to_string().into(),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0218", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_success_with_related_key() {
    // GIVEN
    let (context, organisation, did, _, key) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            verifier_key: Some(key.id.to_string().into()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_FINAL1");
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
        .await
        .unwrap()
        .first()
        .unwrap()
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
          "verificationProtocol": "OPENID4VP_FINAL1",
          "verifierDid": did.id,
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
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
            organisation.clone(),
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
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                schema_id: Some("org.iso.18013.5.1.mDL".to_string()),
                ..Default::default()
            },
        )
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            ..Default::default()
        })
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
            organisation.clone(),
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
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            ..Default::default()
        })
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
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create_with_identifier(
            &proof_schema.id.to_string(),
            "OPENID4VP_FINAL1",
            &identifier.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_proof_certificate_without_authentication_role() {
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

    // Create certificate with only AssertionMethod role (no Authentication)
    let _certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams {
                key: Some(key),
                roles: Some(vec![CertificateRole::AssertionMethod]),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create_with_identifier(
            &proof_schema.id.to_string(),
            "OPENID4VP_FINAL1",
            &identifier.id,
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0222", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_success_with_profile() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    let test_profile = "test-profile-123";

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            profile: Some(test_profile),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.protocol, "OPENID4VP_FINAL1");
    assert_eq!(proof.transport, "HTTP");

    // Verify the profile is correctly stored
    assert_eq!(proof.profile.as_ref().unwrap(), test_profile);

    assert_history_count(&context, &proof.id.into(), HistoryAction::Created, 1).await;
}

#[tokio::test]
async fn test_create_proof_success_with_webhook_url() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    let webhook_url = "https://testing.url";

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            webhook_destination_url: Some(webhook_url),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;

    assert!(resp.get("id").is_some());

    let proof = context.db.proofs.get(&resp["id"].parse()).await;
    assert_eq!(proof.webhook_url.unwrap(), webhook_url);
}

#[tokio::test]
async fn test_create_proof_fails_with_engagement_on_non_iso_mdl_protocol() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            engagement: Some("QR_CODE"),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp: Value = resp.json().await;
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0272");
    assert_eq!(
        resp["message"].as_str().unwrap(),
        "Engagement provided for non ISO mDL flow"
    );
}

#[tokio::test]
async fn test_create_proof_fails_with_iso_mdl_engagement_and_none_engagement() {
    // GIVEN
    let config = indoc::indoc! {"
        verificationProtocol:
            ISO_MDL:
                type: 'ISO_MDL'
                display: 'exchange.isoMdl'
                order: 4
    "}
    .to_string();
    let (context, organisation, did, ..) = TestContext::new_with_did(Some(config)).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "ISO_MDL".into(),
            verifier_did: did.id.to_string().into(),
            iso_mdl_engagement: Some("ISO_MDL_ENGAGEMENT"),
            engagement: None,
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp: Value = resp.json().await;
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0079");
    assert_eq!(
        resp["message"].as_str().unwrap(),
        "Engagement missing for ISO mDL flow"
    );
}

#[tokio::test]
async fn test_create_proof_fails_with_iso_mdl_engagement_and_invalid_engagement() {
    // GIVEN
    let config = indoc::indoc! {"
        verificationProtocol:
            ISO_MDL:
                type: 'ISO_MDL'
                display: 'exchange.isoMdl'
                order: 4
    "}
    .to_string();
    let (context, organisation, did, ..) = TestContext::new_with_did(Some(config)).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "ISO_MDL".into(),
            verifier_did: did.id.to_string().into(),
            iso_mdl_engagement: Some("ISO_MDL_ENGAGEMENT"),
            engagement: Some("INVALID_ENGAGEMENT"),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp: Value = resp.json().await;
    assert_eq!(resp["code"].as_str().unwrap(), "BR_0077");
    assert_eq!(
        resp["message"].as_str().unwrap(),
        "Verification engagement not enabled"
    );
}

async fn tx_data_proof_schema_setup(
    format: &str,
) -> (
    TestContext,
    Organisation,
    Did,
    CredentialSchema,
    ProofSchema,
) {
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some(format.to_string().into()),
                ..Default::default()
            },
        )
        .await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
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
            }],
        )
        .await;
    (context, organisation, did, credential_schema, proof_schema)
}

#[tokio::test]
async fn test_create_proof_with_transaction_data_success() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let claim_schemas: Vec<_> = vec![
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
            "namespace",
            true,
            "OBJECT",
            false,
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap(),
            "namespace/name",
            true,
            "STRING",
            false,
        ),
    ];
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "test",
            &organisation,
            &claim_schemas,
            "MDOC",
            "org.iso.18013.5.1.mDL",
        )
        .await;
    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            vec![CreateProofInputSchema::from((
                &claim_schemas[..],
                &credential_schema,
            ))],
        )
        .await;

    // WHEN
    let tx_data = json!({
      "numSignatures": 2,
      "signatureQualifier": "eu_eidas_qes",
      "documentInfos": [
        {
          "label": "Example Contract",
          "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
          "hashType": "sodr",
          "access": {
            "type": "OTP",
            "oneTimePassword": "51623"
          },
          "href": "https://protected.rp.example/contract-01.pdf?token=HS9naJKWwp901hBcK348IUHiuH8374",
          "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
        },
        {
          "label": "Example Terms of Service",
          "hash": "HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0=",
          "hashType": "sodr",
          "access": {
            "type": "public"
          },
          "href": "https://public.rp-cdn.example/terms-and-conditions.pdf",
          "checksum": "sha256-HZQzZmMAIWekfGH0/ZKW1nsdt0xg3H6bZYztgsMTLw0="
        },
        {
          "label": "Example Invoice",
          "hash": "nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ=",
          "hashType": "sodr",
          "access": {
            "type": "OTP",
            "oneTimePassword": "83920"
          },
          "href": "https://protected.rp.example/invoice-2025-07.pdf?token=jk47ns88sna9a",
          "checksum": "sha256-nL7zQmAKfQ2jADrOxkEZh2UqV4Lx4WsmelSivP6LjoQ="
        }
      ],
      "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
    });
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "QES_APPROVAL",
                "credentialSchemaIds": [credential_schema.id.to_string()],
                "data": tx_data
            }])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp: Value = resp.json().await;
    let proof_id = resp["id"].parse();

    // the create-time interaction already carries the mapped transaction data
    let proof = context.db.proofs.get(&proof_id).await;
    let data: Value = serde_json::from_slice(
        proof
            .interaction
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .data
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["transaction_data"][0]["type"], json!("QES_APPROVAL"));
    assert_eq!(
        data["transaction_data"][0]["credential_ids"],
        json!([credential_schema.formats.as_ref().await.unwrap()[0]
            .id
            .to_string()])
    );
    assert_eq!(data["transaction_data"][0]["data"], tx_data);

    // and it lands in the verifier interaction content when the proof is shared
    assert_eq!(201, context.api.proofs.share(proof_id, None).await.status());
    let proof = context.db.proofs.get(&proof_id).await;
    let data: Value = serde_json::from_slice(
        proof
            .interaction
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .data
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(data["transaction_data"][0]["type"], json!("QES_APPROVAL"));
    assert_eq!(
        data["transaction_data"][0]["credential_ids"],
        json!([credential_schema.formats.as_ref().await.unwrap()[0]
            .id
            .to_string()])
    );
    assert_eq!(data["transaction_data"][0]["data"], tx_data);
}

#[tokio::test]
async fn test_create_proof_with_invalid_transaction_data() {
    // GIVEN
    let (context, _organisation, did, credential_schema, proof_schema) =
        tx_data_proof_schema_setup("SD_JWT_VC").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "QES_APPROVAL",
                "credentialSchemaIds": [credential_schema.id.to_string()],
                "data": { "foo": "bar" }
            }])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0458", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_with_transaction_data_provider_not_found() {
    // GIVEN
    let (context, _organisation, did, credential_schema, proof_schema) =
        tx_data_proof_schema_setup("SD_JWT_VC").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "NONEXISTENT_PROVIDER",
                "credentialSchemaIds": [credential_schema.id.to_string()],
            }])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0430", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_with_transaction_data_unknown_credential_schema() {
    // GIVEN
    let (context, _organisation, did, _credential_schema, proof_schema) =
        tx_data_proof_schema_setup("SD_JWT_VC").await;

    // WHEN — referenced credential schema is not part of the proof schema
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "QES_APPROVAL",
                "credentialSchemaIds": [Uuid::new_v4().to_string()],
            }])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0461", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_with_transaction_data_format_unsupported() {
    // GIVEN — JWT credential schema does not support transaction data
    let (context, _organisation, did, credential_schema, proof_schema) =
        tx_data_proof_schema_setup("JWT").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "QES_APPROVAL",
                "credentialSchemaIds": [credential_schema.id.to_string()],
            }])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0460", resp.error_code().await);
}

#[tokio::test]
async fn test_create_proof_with_more_transaction_data_entries_than_credentials() {
    // GIVEN
    let (context, _organisation, did, credential_schema, proof_schema) =
        tx_data_proof_schema_setup("SD_JWT_VC").await;

    let document_info = |label: &str| {
        json!({
            "label": label,
            "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
            "hashType": "sodr",
            "access": { "type": "public" },
            "href": "https://public.rp-cdn.example/contract.pdf",
            "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
        })
    };

    // WHEN — two QES approval entries can only be authorized by the same
    // single credential schema
    let resp = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([
                {
                    "type": "QES_APPROVAL",
                    "credentialSchemaIds": [credential_schema.id.to_string()],
                    "data": {
                        "numSignatures": 1,
                        "signatureQualifier": "eu_eidas_qes",
                        "documentInfos": [document_info("Example Contract")],
                        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
                    }
                },
                {
                    "type": "QES_APPROVAL",
                    "credentialSchemaIds": [credential_schema.id.to_string()],
                    "data": {
                        "numSignatures": 1,
                        "signatureQualifier": "eu_eidas_qes",
                        "documentInfos": [document_info("Example Invoice")],
                        "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
                    }
                }
            ])),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0463", resp.error_code().await);
}

async fn multiformat_proof_schema_setup(
    formats: &[&str],
) -> (TestContext, Did, CredentialSchema, ProofSchema) {
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let schema = context
        .db
        .credential_schemas
        .create(
            "Multi-format credential",
            &organisation,
            TestingCreateSchemaParams {
                formats: Some(
                    formats
                        .iter()
                        .map(|name| ((*name).into(), format!("{name}-schema")))
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await;
    let claim = schema.claim_schemas.as_ref().await.unwrap()[0].clone();
    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "Multi-format proof",
            &organisation,
            vec![CreateProofInputSchema {
                credential_schema: &schema,
                claims: vec![CreateProofClaim {
                    id: claim.id,
                    key: &claim.key,
                    required: true,
                    data_type: &claim.data_type,
                    array: false,
                }],
            }],
        )
        .await;
    (context, did, schema, proof_schema)
}

fn multiformat_transaction_entry(
    schema_id: shared_types::CredentialSchemaId,
    label: &str,
) -> Value {
    json!({
        "type": "QES_APPROVAL",
        "credentialSchemaIds": [schema_id],
        "data": {
            "numSignatures": 1,
            "signatureQualifier": "eu_eidas_qes",
            "documentInfos": [{
                "label": label,
                "hash": "sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI=",
                "hashType": "sodr", "access": {"type": "public"},
                "href": "https://example.com/contract.pdf",
                "checksum": "sha256-sTOgwOm+474gFj0q0x1iSNspKqbcse4IeiqlDg/HWuI="
            }],
            "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"
        }
    })
}

#[tokio::test]
async fn test_create_proof_with_multiple_selected_formats() {
    let (context, did, _, proof_schema) =
        multiformat_proof_schema_setup(&["SD_JWT_VC", "JWT"]).await;
    let response = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), 201);
    let proof = context
        .db
        .proofs
        .get(&response.json_value().await["id"].parse())
        .await;
    assert_eq!(proof.schema.as_ref().unwrap().id(), proof_schema.id);
    assert_eq!(proof.state, one_core::model::proof::ProofStateEnum::Created);
}

#[tokio::test]
async fn test_create_proof_expands_transaction_data_to_selected_format_ids() {
    use ct_codecs::{Base64UrlSafeNoPadding, Decoder};

    let (context, did, schema, proof_schema) =
        multiformat_proof_schema_setup(&["SD_JWT_VC", "MDOC"]).await;
    let entry = multiformat_transaction_entry(schema.id, "Contract");
    let response = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([entry])),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), 201);
    let proof_id = response.json_value().await["id"].parse();
    let proof = context.db.proofs.get(&proof_id).await;
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let data: Value = serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    let expected_ids: Vec<_> = schema
        .formats
        .as_ref()
        .await
        .unwrap()
        .iter()
        .map(|format| format.id)
        .collect();
    assert_eq!(
        data["transaction_data"][0]["credential_ids"],
        json!(expected_ids)
    );
    assert_eq!(data["transaction_data"][0]["data"], entry["data"]);
    let encoded = data["transaction_data"][0]["encoded"].as_str().unwrap();
    let decoded: Value =
        serde_json::from_slice(&Base64UrlSafeNoPadding::decode_to_vec(encoded, None).unwrap())
            .unwrap();
    assert_eq!(decoded["credential_ids"], json!(expected_ids));
}

#[tokio::test]
async fn test_create_proof_format_alternatives_do_not_increase_transaction_capacity() {
    let (context, did, schema, proof_schema) =
        multiformat_proof_schema_setup(&["SD_JWT_VC", "MDOC"]).await;
    let response = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([
                multiformat_transaction_entry(schema.id, "Contract"),
                multiformat_transaction_entry(schema.id, "Invoice")
            ])),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0463");
}

#[tokio::test]
async fn test_create_proof_rejects_selected_format_without_transaction_support() {
    let (context, did, schema, proof_schema) =
        multiformat_proof_schema_setup(&["SD_JWT_VC", "JWT"]).await;
    let response = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([multiformat_transaction_entry(
                schema.id, "Contract"
            )])),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0460");
}

#[tokio::test]
async fn test_create_proof_rejects_selected_format_unsupported_by_transaction_type() {
    let (context, did, schema, proof_schema) =
        multiformat_proof_schema_setup(&["SD_JWT_VC", "MDOC"]).await;
    let response = context
        .api
        .proofs
        .create(CreateProofTestParams {
            proof_schema_id: proof_schema.id.to_string().into(),
            protocol: "OPENID4VP_FINAL1".into(),
            verifier_did: did.id.to_string().into(),
            transaction_data: Some(json!([{
                "type": "SCA_LOGIN_RISK_TRANSACTION",
                "credentialSchemaIds": [schema.id]
            }])),
            ..Default::default()
        })
        .await;
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0460");
}
