use std::str::FromStr;

use assert2::let_assert;
use core_server::endpoint::proof::dto::ClientIdSchemeRestEnum;
use one_core::config::core_config::VerificationProtocolType;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::history::HistoryAction;
use one_core::model::identifier::{Identifier, IdentifierData, IdentifierType};
use one_core::model::proof::{Proof, ProofRole, ProofStateEnum};
use serde_json::Value;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use url::Url;
use uuid::Uuid;

use crate::fixtures::{self, TestingDidParams, TestingIdentifierParams, assert_history_count};
use crate::utils::api_clients::Response;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::db_clients::proofs::TestingProofParams;

#[tokio::test]
async fn test_share_proof_success() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1",
        None,
        Some(&key),
        None,
        None,
    )
    .await;

    // WHEN
    let resp = context.api.proofs.share(proof.id, None).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json::<Value>().await;
    let url = resp["url"].as_str().unwrap();
    assert!(url.starts_with("openid4vp"));
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_key_storage_disabled_success() {
    // check that sharing works also when using disabled key storage
    let additional_config = Some(
        indoc::indoc! {"
      keyStorage:
        INTERNAL:
          enabled: false
  "}
        .to_string(),
    );
    // GIVEN
    let (context, organisation, _, identifier, key) =
        TestContext::new_with_did(additional_config).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    for exchange in ["OPENID4VP_FINAL1"] {
        let proof = fixtures::create_proof(
            &context.db.db_conn,
            &identifier,
            Some(&proof_schema),
            ProofStateEnum::Created,
            ProofRole::Verifier,
            exchange,
            None,
            Some(&key),
            None,
            None,
        )
        .await;

        // WHEN
        let resp = context.api.proofs.share(proof.id, None).await;

        // THEN
        assert_eq!(resp.status(), 201);
        let resp = resp.json::<Value>().await;
        let url = resp["url"].as_str().unwrap();
        assert!(url.starts_with("openid4vp"));
        assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
    }
}

#[tokio::test]
async fn test_share_proof_twice() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1",
        None,
        Some(&key),
        None,
        None,
    )
    .await;

    // WHEN
    let resp_1 = context.api.proofs.share(proof.id, None).await;
    let resp_2 = context.api.proofs.share(proof.id, None).await;

    // THEN
    assert_eq!(resp_1.status(), 201);
    assert_eq!(resp_2.status(), 201);

    let resp_1 = resp_1.json::<Value>().await;
    let url_1 = resp_1["url"].as_str().unwrap();
    let resp_2 = resp_2.json::<Value>().await;
    let url_2 = resp_2["url"].as_str().unwrap();
    assert_eq!(url_1, url_2);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 2).await;
}

#[tokio::test]
async fn test_share_proof_success_with_separate_encryption_key() {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let signing_key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;

    let encryption_key = context
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
                        key: signing_key.clone(),
                        role: KeyRole::AssertionMethod,
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        key: signing_key.clone(),
                        role: KeyRole::Authentication,
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        key: encryption_key.clone(),
                        role: KeyRole::KeyAgreement,
                        reference: "2".to_string(),
                    },
                ]),
                did: Some(
                    DidValue::from_str("did:key:zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ")
                        .unwrap(),
                ),
                ..Default::default()
            },
        )
        .await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap(),
        "location_x",
        true,
        "STRING",
        false,
    )];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "test",
            &organisation,
            &claim_schemas,
            "JSON_LD_CLASSIC",
            "test",
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

    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(false),
                ..Default::default()
            },
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(signing_key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(201, context.api.proofs.share(proof.id, None).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let data: Value = serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();

    assert_eq!(data["encryption_key"]["kid"], encryption_key.id.to_string());
}

#[tokio::test]
async fn test_share_proof_success_mdoc() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
            "namespace",
            true,
            "OBJECT",
            false,
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap(),
            "namespace/location",
            true,
            "OBJECT",
            false,
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap(),
            "namespace/location/X",
            true,
            "STRING",
            false,
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c43").unwrap(),
            "namespace/location/Y",
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

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            VerificationProtocolType::OpenId4VpFinal1_0.as_ref(),
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(201, context.api.proofs.share(proof.id, None).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let data: Value = serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    let mut credential_query = data["dcql_query"]["credentials"][0].to_owned();
    credential_query["id"] = serde_json::json!("CREDENTIAL_ID");

    let expected = serde_json::json!({
        "id": "CREDENTIAL_ID",
        "format": "mso_mdoc",
        "multiple": false,
        "require_cryptographic_holder_binding": true,
        "meta": {
          "doctype_value": "org.iso.18013.5.1.mDL"
        },
        "claims": [
          {
            "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
            "intent_to_retain": true,
            "path": ["namespace"],
            "required": true
          },
          {
            "id": "48db4654-01c4-4a43-9df4-300f1f425c41",
            "intent_to_retain": true,
            "path": ["namespace", "location"],
            "required": true
          },
          {
            "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
            "intent_to_retain": true,
            "path": ["namespace", "location", "X"],
            "required": true
          },
          {
            "id": "48db4654-01c4-4a43-9df4-300f1f425c43",
            "intent_to_retain": true,
            "path": ["namespace", "location", "Y"],
            "required": true
          }
        ]
    });

    assert_eq!(expected, credential_query);
}

#[tokio::test]
async fn test_share_proof_success_jsonld() {
    // check that sharing works also when not using request_uri
    let additional_config = Some(
        indoc::indoc! {"
      exchange:
        OPENID4VC:
          params:
            public:
              useRequestUri: false
  "}
        .to_string(),
    );
    let (context, organisation, _, identifier, key) =
        TestContext::new_with_did(additional_config).await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap(),
        "location_x",
        true,
        "STRING",
        false,
    )];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "test",
            &organisation,
            &claim_schemas,
            "JSON_LD_CLASSIC",
            "test",
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

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            "OPENID4VP_FINAL1",
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    assert_eq!(201, context.api.proofs.share(proof.id, None).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let data: Value = serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    let mut credential_query = data["dcql_query"]["credentials"][0].to_owned();
    credential_query["id"] = serde_json::json!("CREDENTIAL_ID");

    let expected = serde_json::json!({
        "id": "CREDENTIAL_ID",
        "format": "ldp_vc",
        "multiple": false,
        "require_cryptographic_holder_binding": true,
        "meta": {
          "type_values": [
            ["https://www.w3.org/2018/credentials#VerifiableCredential", "test#Test"],
            ["Test"]
          ]
        },
        "claims": [
          {
            "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
            "path": ["credentialSubject", "location_x"],
            "required": true
          }
        ]
    });

    assert_eq!(expected, credential_query);
}

async fn prepare_created_openid4vp_proof(exchange: Option<&str>) -> (TestContext, Proof) {
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Created,
        ProofRole::Verifier,
        exchange.unwrap_or("OPENID4VP_FINAL1"),
        None,
        Some(&key),
        None,
        None,
    )
    .await;

    (context, proof)
}

async fn prepare_created_certificate_openid4vp_proof(exchange: &str) -> (TestContext, Proof) {
    let (context, organisation, identifier, _, key) =
        TestContext::new_with_certificate_identifier(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            exchange,
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_key: Some(key),
                proof_schema: Some(proof_schema),
                ..Default::default()
            },
        )
        .await;

    (context, proof)
}

async fn extract_client_id(response: Response) -> String {
    assert_eq!(response.status(), 201);
    let resp = response.json::<Value>().await;
    let url = resp["url"].as_str().unwrap();
    let url = Url::parse(url).unwrap();
    let client_id = url
        .query_pairs()
        .find(|(key, _)| key == "client_id")
        .unwrap()
        .1;
    client_id.to_string()
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_redirect_uri_openid4vp_final1_0() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof(Some("OPENID4VP_FINAL1")).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(proof.id, Some(ClientIdSchemeRestEnum::RedirectUri))
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;
    assert_eq!(
        client_id,
        format!(
            "redirect_uri:{}/ssi/openid4vp/final-1.0/response",
            context.config.app.core_base_url
        )
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_did_openid4vp_draft20() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof(None).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(
            proof.id,
            Some(ClientIdSchemeRestEnum::DecentralizedIdentifier),
        )
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;
    let_assert!(
        Identifier {
            data: IdentifierData::Did(verifier_did),
            ..
        } = proof
            .verifier_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    assert_eq!(
        client_id,
        format!(
            "decentralized_identifier:{}",
            verifier_did.as_ref().await.unwrap().did
        )
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_verifier_attestation_openid4vp_final1_0() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof(None).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(proof.id, Some(ClientIdSchemeRestEnum::VerifierAttestation))
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;
    assert_eq!(
        client_id,
        format!(
            "verifier_attestation:{}/ssi/openid4vp/final-1.0/response",
            context.config.app.core_base_url
        )
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_did_openid4vp_final1_0() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof(Some("OPENID4VP_FINAL1")).await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(
            proof.id,
            Some(ClientIdSchemeRestEnum::DecentralizedIdentifier),
        )
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;

    let_assert!(
        Identifier {
            data: IdentifierData::Did(verifier_identifier_did),
            ..
        } = proof
            .verifier_identifier
            .as_ref()
            .unwrap()
            .as_ref()
            .await
            .unwrap()
            .to_owned()
    );
    let verifier_did = verifier_identifier_did
        .as_ref()
        .await
        .unwrap()
        .did
        .to_string();

    assert_eq!(
        client_id,
        format!("decentralized_identifier:{verifier_did}")
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_x509_hash_openid4vp_final1_0() {
    // GIVEN
    let (context, proof) = prepare_created_certificate_openid4vp_proof("OPENID4VP_FINAL1").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(proof.id, Some(ClientIdSchemeRestEnum::X509Hash))
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;
    assert_eq!(client_id, format!("x509_hash:__-qqg"));

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_openid4vp_final1_haip_defaults_to_x509_hash() {
    // GIVEN
    let (context, proof) =
        prepare_created_certificate_openid4vp_proof("OPENID4VP_FINAL1_HAIP").await;

    // WHEN
    let resp = context.api.proofs.share(proof.id, None).await;

    // THEN
    let client_id = extract_client_id(resp).await;
    assert_eq!(client_id, format!("x509_hash:__-qqg"));

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_fails_when_nfc_engagement_is_set_on_proof() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .await
        .unwrap()
        .first()
        .unwrap()
        .to_owned();

    let proof_schema = fixtures::create_proof_schema(
        &context.db.db_conn,
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

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "ISO_MDL",
        None,
        Some(&key),
        None,
        Some("NFC".to_string()),
    )
    .await;

    // WHEN
    let resp = context.api.proofs.share(proof.id, None).await;

    // THEN
    assert_eq!(resp.status(), 400);
    let resp = resp.json::<Value>().await;
    assert_eq!(&resp["code"], "BR_0078");
    assert_eq!(
        &resp["message"],
        "Sharing not possible with non QR_CODE engagement"
    );
}
