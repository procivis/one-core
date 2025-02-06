use std::str::FromStr;

use one_core::model::history::HistoryAction;
use one_core::model::proof::ProofStateEnum;
use serde_json::Value;
use uuid::Uuid;

use crate::fixtures::assert_history_count;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::{fixtures, utils};

#[tokio::test]
async fn test_share_proof_success() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did(None).await;
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
        None,
        Some(&proof_schema),
        ProofStateEnum::Created,
        "OPENID4VC",
        None,
    )
    .await;

    // WHEN
    let url = format!(
        "{}/api/proof-request/v1/{}/share",
        context.config.app.core_base_url, proof.id
    );
    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await.unwrap();
    let url = resp["url"].as_str().unwrap();
    assert!(url.starts_with("openid4vp"));
    assert_history_count(&context, &proof.id.into(), HistoryAction::Shared, 1).await;
}

#[tokio::test]
async fn test_share_proof_success_mdoc() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;

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
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            key,
        )
        .await;

    assert_eq!(200, context.api.proofs.share(proof.id).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.unwrap();
    let data: Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    let input_descriptor = data["presentation_definition"]["input_descriptors"][0].to_owned();

    let expected = serde_json::json!({
        "constraints": {
          "fields": [
            {
              "filter": {
                "const": "org.iso.18013.5.1.mDL",
                "type": "string"
              },
              "id": null,
              "name": null,
              "purpose": null,
              "optional": null,
              "path": [
                "$.credentialSchema.id"
              ]
            },
            {
              "id": "48db4654-01c4-4a43-9df4-300f1f425c40",
              "path": [
                  "$['namespace']"
              ],
              "name": null,
              "purpose": null,
              "optional": false,
              "filter": null,
              "intent_to_retain": true
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c41",
              "name": null,
              "purpose": null,
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location']"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
              "name": null,
              "purpose": null,
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/X']"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c43",
              "name": null,
              "purpose": null,
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/Y']"
              ]
            }
          ],
          "validity_credential_nbf": null,
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
        "name": "test",
        "purpose": null
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
    let (context, organisation, did, key) = TestContext::new_with_did(additional_config).await;

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
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VC",
            None,
            key,
        )
        .await;

    assert_eq!(200, context.api.proofs.share(proof.id).await.status());

    let proof = context.db.proofs.get(&proof.id).await;
    let interaction = proof.interaction.unwrap();
    let data: Value = serde_json::from_slice(&interaction.data.unwrap()).unwrap();
    let input_descriptor = data["presentation_definition"]["input_descriptors"][0].to_owned();

    let expected = serde_json::json!({
        "id": "input_0",
        "name": "test",
        "purpose": null,
        "constraints": {
          "fields": [
            {
              "filter": {
                "const": "test",
                "type": "string"
              },
              "id": null,
              "name": null,
              "purpose": null,
              "optional": null,
              "path": [
                "$.credentialSchema.id"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
              "name": null,
              "purpose": null,
              "optional": false,
              "path": [
                "$.vc.credentialSubject.location_x"
              ]
            }
          ],
          "validity_credential_nbf": null
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
