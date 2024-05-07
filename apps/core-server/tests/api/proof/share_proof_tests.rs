use one_core::model::proof::ProofStateEnum;
use serde_json::Value;
use std::str::FromStr;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::{
    fixtures,
    utils::{
        self,
        db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema},
        server::run_server,
    },
};

#[tokio::test]
async fn test_share_proof_success() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;

    let organisation = fixtures::create_organisation(&db_conn).await;

    let credential_schema =
        fixtures::create_credential_schema(&db_conn, "test", &organisation, "NONE").await;
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
            }],
            credential_schema: &credential_schema,
            validity_constraint: None,
        }],
    )
    .await;

    let did = fixtures::create_did(&db_conn, &organisation, None).await;

    let proof = fixtures::create_proof(
        &db_conn,
        &did,
        None,
        Some(&proof_schema),
        ProofStateEnum::Created,
        "PROCIVIS_TEMPORARY",
        None,
    )
    .await;

    // WHEN
    let _handle = run_server(listener, config, &db_conn);

    let url = format!("{base_url}/api/proof-request/v1/{}/share", proof.id);
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
    assert!(url.ends_with(&format!(
        "/ssi/temporary-verifier/v1/connect?protocol={}&proof={}",
        "PROCIVIS_TEMPORARY", proof.id
    )));
}

#[tokio::test]
async fn test_share_proof_success_mdoc() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did().await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c40").unwrap(),
            "namespace",
            true,
            "OBJECT",
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c41").unwrap(),
            "namespace/location",
            true,
            "OBJECT",
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap(),
            "namespace/location/X",
            true,
            "STRING",
        ),
        (
            Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c43").unwrap(),
            "namespace/location/Y",
            true,
            "STRING",
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
            "test",
        )
        .await;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema::from((&claim_schemas[..], &credential_schema)),
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
                "const": "test",
                "type": "string"
              },
              "id": null,
              "optional": null,
              "path": [
                "$.credentialSchema.id"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c41",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location']"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/X']"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c43",
              "intent_to_retain": true,
              "optional": false,
              "path": [
                "$['namespace']['location/Y']"
              ]
            }
          ],
          "validity_credential_nbf": null
        },
        "format": {
          "mso_mdoc": {
            "alg": [
              "EdDSA",
              "ES256"
            ]
          }
        },
        "id": "input_0"
    });

    assert_eq!(expected, input_descriptor);
}

#[tokio::test]
async fn test_share_proof_success_jsonld() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did().await;

    let claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![(
        Uuid::from_str("48db4654-01c4-4a43-9df4-300f1f425c42").unwrap(),
        "location_x",
        true,
        "STRING",
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
            CreateProofInputSchema::from((&claim_schemas[..], &credential_schema)),
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
                "const": "test",
                "type": "string"
              },
              "id": null,
              "optional": null,
              "path": [
                "$.credentialSchema.id"
              ]
            },
            {
              "filter": null,
              "id": "48db4654-01c4-4a43-9df4-300f1f425c42",
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
        },
        "id": "input_0"
    });

    assert_eq!(expected, input_descriptor);
}
