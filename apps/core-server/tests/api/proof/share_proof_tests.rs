use std::str::FromStr;

use core_server::endpoint::proof::dto::ClientIdSchemeRestEnum;
use one_core::config::core_config::VerificationProtocolType;
use one_core::model::history::HistoryAction;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::Value;
use url::Url;
use uuid::Uuid;

use crate::fixtures;
use crate::fixtures::assert_history_count;
use crate::utils::api_clients::Response;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_share_proof_success() {
    // GIVEN
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
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
            validity_constraint: None,
        }],
    )
    .await;

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &did,
        &identifier,
        None,
        None,
        Some(&proof_schema),
        ProofStateEnum::Created,
        "OPENID4VP_DRAFT20",
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
async fn test_share_proof_success_mdoc() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

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
            "NONE",
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
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            VerificationProtocolType::OpenId4VpDraft20.as_ref(),
            None,
            key,
        )
        .await;

    assert_eq!(201, context.api.proofs.share(proof.id, None).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.unwrap();
    let data: Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    let input_descriptor = data["presentation_definition"]["input_descriptors"][0].to_owned();

    let expected = serde_json::json!({
        "constraints": {
          "fields": [
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
              "path": [
                  "$['namespace']"
              ],
              "optional": false,
              "intent_to_retain": true
            },
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c41",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location']"
              ]
            },
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/X']"
              ]
            },
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c43",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/Y']"
              ]
            }
          ],
          "limit_disclosure": "required"
        },
        "format": {
          "mso_mdoc": {
            "alg": [
              "EdDSA",
              "ES256"
            ]
          }
        },
        "id": "org.iso.18013.5.1.mDL",
        "name": "test"
    });

    assert_eq!(expected, input_descriptor);
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
    let (context, organisation, did, identifier, key) =
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
            "NONE",
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
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            None,
            key,
        )
        .await;

    assert_eq!(201, context.api.proofs.share(proof.id, None).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.unwrap();
    let data: Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    let input_descriptor = data["presentation_definition"]["input_descriptors"][0].to_owned();

    let expected = serde_json::json!({
        "id": "input_0",
        "name": "test",
        "constraints": {
          "fields": [
            {
              "filter": {
                "const": "test",
                "type": "string"
              },
              "path": [
                "$.credentialSchema.id"
              ]
            },
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
              "optional": false,
              "path": [
                "$.vc.credentialSubject.location_x"
              ]
            }
          ]
        },
        "format": {
          "ldp_vc": {
            "proof_type": [
              "DataIntegrityProof"
            ]
          }
        }
    });

    assert_eq!(expected, input_descriptor);
}

async fn prepare_created_openid4vp_proof() -> (TestContext, Proof) {
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &organisation, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .schema
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
            validity_constraint: None,
        }],
    )
    .await;

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &did,
        &identifier,
        None,
        None,
        Some(&proof_schema),
        ProofStateEnum::Created,
        "OPENID4VP_DRAFT20",
        None,
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
async fn test_share_proof_client_id_scheme_redirect_uri() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof().await;

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
            "{}/ssi/openid4vp/draft-20/response",
            context.config.app.core_base_url
        )
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_did() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof().await;

    // WHEN
    let resp = context
        .api
        .proofs
        .share(proof.id, Some(ClientIdSchemeRestEnum::Did))
        .await;

    // THEN
    let client_id = extract_client_id(resp).await;
    assert_eq!(client_id, proof.verifier_did.unwrap().did.to_string());

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_client_id_scheme_verifier_attestation() {
    // GIVEN
    let (context, proof) = prepare_created_openid4vp_proof().await;

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
            "{}/ssi/openid4vp/draft-20/response",
            context.config.app.core_base_url
        )
    );

    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}
