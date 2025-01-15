use one_core::model::proof::ProofStateEnum;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_get_client_metadata() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            None,
            key.to_owned(),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(
        resp,
        serde_json::json!({
            "jwks": [
                {
                    "crv": "P-256",
                    "kid": key.id.to_string(),
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }
            ],
            "client_id_scheme": "redirect_uri",
            "vp_formats": {
                "jwt_vc_json": {
                    "alg": ["EdDSA", "ES256"]
                },
                "jwt_vp_json": {
                    "alg": ["EdDSA", "ES256"]
                },
                "ldp_vc": {
                    "alg": ["EdDSA", "ES256", "BLS12-381G1-SHA256"]
                },
                "ldp_vp": {
                    "alg": ["EdDSA", "ES256"]
                },
                "mso_mdoc": {
                    "alg": ["EdDSA", "ES256"]
                },
                "vc+sd-jwt": {
                    "alg": ["EdDSA", "ES256"]
                }
            },
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
        })
    );
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_unknown_proof_id() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_wrong_exchange_protocol() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "SCAN_TO_VERIFY",
            None,
            key,
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_wrong_proof_state() {
    // GIVEN
    let (context, organisation, did, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

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

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Rejected,
            "OPENID4VC",
            None,
            key,
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}
