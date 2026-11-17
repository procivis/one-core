use ciborium::cbor;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::history::HistoryAction;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use standardized_types::openid4vp::dc_api::{DigitalCredential, IsoMdocResponse};

use crate::fixtures::assert_history_count;
use crate::utils::api_clients::proofs::ShareProofTestParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::db_clients::proofs::TestingProofParams;

/// Creates an MDOC proof using the given `protocol` over DC_API and shares it, leaving it in the `PENDING` state
async fn prepare_pending_dc_api_proof(protocol: &str) -> (TestContext, Proof) {
    let (context, organisation, identifier, certificate, key) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                schema_id: Some("org.iso.18013.5.1.mDL".to_string()),
                claim_namespace: Some("org.iso.18013.5.1".to_string()),
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

    let proof = context
        .db
        .proofs
        .create(
            ProofStateEnum::Created,
            protocol,
            TestingProofParams {
                verifier_identifier: Some(identifier),
                verifier_certificate: Some(certificate),
                verifier_key: Some(key),
                proof_schema: Some(proof_schema),
                transport: Some("DC_API".to_string()),
                ..Default::default()
            },
        )
        .await;

    let resp = context
        .api
        .proofs
        .share(
            proof.id,
            ShareProofTestParams {
                dc_api_origin: Some("https://verifier.example.com"),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 201);

    let proof = context.db.proofs.get(&proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Pending);

    (context, proof)
}

fn dummy_iso_mdl_dc_api_response() -> String {
    let encrypted_response = cbor!([
        "dcapi",
        {
            "enc" => ciborium::Value::Bytes(vec![0x04; 65]),
            "cipherText" => ciborium::Value::Bytes(vec![1, 2]),
        }
    ])
    .unwrap();

    let mut encrypted_response_bytes = vec![];
    ciborium::into_writer(&encrypted_response, &mut encrypted_response_bytes).unwrap();

    let response = DigitalCredential::OrgIsoMdoc(IsoMdocResponse {
        response: Base64UrlSafeNoPadding::encode_to_string(encrypted_response_bytes).unwrap(),
    });

    serde_json::to_string(&response).unwrap()
}

/// Builds an OpenID4VP DC-API response containing an invalid mdoc presentation for the
/// (single) DCQL credential query stored in the proof interaction
async fn dummy_openid4vp_dc_api_response(proof: &Proof) -> String {
    let interaction = proof.interaction.as_ref().unwrap().as_ref().await.unwrap();
    let interaction_data: Value =
        serde_json::from_slice(interaction.data.as_ref().unwrap()).unwrap();
    let query_id = interaction_data["dcql_query"]["credentials"][0]["id"]
        .as_str()
        .unwrap();

    let invalid_device_response = Base64UrlSafeNoPadding::encode_to_string([1, 2, 3]).unwrap();
    let response = DigitalCredential::OpenID4VpV1Signed(json!({
        "vp_token": {
            query_id: [invalid_device_response]
        }
    }));

    serde_json::to_string(&response).unwrap()
}

#[tokio::test]
async fn test_submit_dc_api_response_invalid_device_response_sets_proof_to_error() {
    // GIVEN
    let (context, proof) = prepare_pending_dc_api_proof("ISO_MDL").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .submit_dc_api_response(proof.id, &dummy_iso_mdl_dc_api_response())
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0528", resp.error_code().await);

    let proof = context.db.proofs.get(&proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Errored, 1).await;
}

#[tokio::test]
async fn test_submit_dc_api_response_openid4vp_haip_invalid_presentation_sets_proof_to_error() {
    // GIVEN
    let (context, proof) = prepare_pending_dc_api_proof("OPENID4VP_FINAL1_HAIP").await;

    // WHEN
    let resp = context
        .api
        .proofs
        .submit_dc_api_response(proof.id, &dummy_openid4vp_dc_api_response(&proof).await)
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0528", resp.error_code().await);

    let proof = context.db.proofs.get(&proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    assert_history_count(&context, &proof.id.into(), HistoryAction::Errored, 1).await;
}
