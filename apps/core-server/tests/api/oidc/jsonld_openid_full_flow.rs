use axum::http::StatusCode;
use one_core::model::{credential::CredentialStateEnum, proof::ProofStateEnum};
use serde_json::json;

use uuid::Uuid;

use crate::{
    api_oidc_tests::full_flow_common::{
        ecdsa_key_1, ecdsa_key_2, eddsa_key_1, eddsa_key_2, prepare_dids,
    },
    fixtures::TestingCredentialParams,
    utils::{context::TestContext, db_clients::proof_schemas::CreateProofInputSchema},
};

use super::full_flow_common::TestKey;

#[tokio::test]
async fn test_openid4vc_jsonld_flow_eddsa_eddsa() {
    test_openid4vc_jsonld_flow(eddsa_key_1(), eddsa_key_2(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_flow_ecdsa_eddsa() {
    test_openid4vc_jsonld_flow(ecdsa_key_1(), eddsa_key_1(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_flow_eddsa_ecdsa() {
    test_openid4vc_jsonld_flow(eddsa_key_1(), ecdsa_key_1(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_flow_ecdsa_ecdsa() {
    test_openid4vc_jsonld_flow(ecdsa_key_1(), ecdsa_key_2(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_flow_eddsa_eddsa_lvvc() {
    test_openid4vc_jsonld_flow(eddsa_key_1(), eddsa_key_2(), "LVVC").await
}

async fn test_openid4vc_jsonld_flow(
    server_key: TestKey,
    holder_key: TestKey,
    revocation_method: &str,
) {
    // GIVEN
    let server_context = TestContext::new().await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    server_context.db.json_ld_contexts.prepare_cache().await;

    let (server_did, holder_did, local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(server_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;

    let new_claim_schemas = vec![(Uuid::new_v4(), "Key", true, "STRING", false)];

    let schema_id = Uuid::new_v4();
    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &server_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
            &schema_id.to_string(),
        )
        .await;

    let credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            server_did.as_ref().unwrap(),
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: holder_did.clone(),
                key: local_key.to_owned(),
                ..Default::default()
            },
        )
        .await;

    server_context
        .server_mock
        .json_ld_context(&credential_schema.id, "Test")
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            CreateProofInputSchema::from((&new_claim_schemas[..], &credential_schema)),
        )
        .await;

    let interaction_id = Uuid::new_v4();

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": interaction_id.to_string(),
            "input_descriptors": [{
                "format": {
                    "ldp_vc": {
                        "proof_type": [
                            "DataIntegrityProof"
                        ]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema.schema_id
                            }
                        },
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.Key"],
                            "optional": false
                        }
                    ]
                }
            }]
        }
    });

    let interaction = server_context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &base_url,
            interaction_data.to_string().as_bytes(),
        )
        .await;

    let proof = server_context
        .db
        .proofs
        .create(
            None,
            &server_did.unwrap(),
            holder_did.as_ref(),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            local_key.unwrap(),
        )
        .await;

    let resp = server_context
        .api
        .ssi
        .temporary_submit(credential.id, holder_did.as_ref().unwrap().did.clone())
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credentials = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;
    holder_context.db.json_ld_contexts.prepare_cache().await;

    let (holder_did, server_did, local_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        Some(holder_key),
        Some(server_key),
    )
    .await;

    let schema_id = Uuid::new_v4();
    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &holder_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
            &credential_schema.schema_id,
        )
        .await;

    let holder_credential = holder_context
        .db
        .credentials
        .create(
            &holder_credential_schema,
            CredentialStateEnum::Accepted,
            server_did.as_ref().unwrap(),
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: holder_did.clone(),
                credential: Some(credentials),
                ..Default::default()
            },
        )
        .await;

    let claims = holder_context
        .db
        .credentials
        .get(&holder_credential.id)
        .await
        .claims
        .unwrap()
        .clone();

    let holder_interaction_data = json!({
        "response_type": "vp_token",
        "state": interaction.id,
        "nonce": nonce,
        "client_id_scheme": "redirect_uri",
        "client_id": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "client_metadata": {
            "jwks": [
                {
                    "crv": "P-256",
                    "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }
            ],
            "vp_formats": {
                "vc+sd-jwt": {
                    "alg": [
                        "EdDSA"
                    ]
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
                "ldp_vc": {
                    "alg": [
                        "EdDSA"
                    ]
                },
                "ldp_vp": {
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
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction.id,
            "input_descriptors": [{
                "format": {
                    "ldp_vc": {
                        "proof_type": [
                            "DataIntegrityProof"
                        ]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": holder_credential_schema.schema_id
                            }
                        },
                        {
                            "id": claims.first().unwrap().id,
                            "path": ["$.vc.credentialSubject.Key"],
                            "optional": false
                        }
                    ]
                }
            }]
        }
    });

    let holder_interaction = holder_context
        .db
        .interactions
        .create(
            None,
            &base_url,
            holder_interaction_data.to_string().as_bytes(),
        )
        .await;

    let holder_proof = holder_context
        .db
        .proofs
        .create(
            Some(proof.id),
            server_did.as_ref().unwrap(),
            holder_did.as_ref(),
            None,
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&holder_interaction),
            local_key.unwrap(),
        )
        .await;

    // WHEN
    let resp = holder_context
        .api
        .interactions
        .presentation_submit(
            holder_interaction.id,
            holder_did.unwrap().id,
            holder_credential.id,
            claims,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    assert_eq!(claims.first().unwrap().claim.value, "test");

    let holder_proof = holder_context.db.proofs.get(&holder_proof.id).await;
    let claims = holder_proof.claims.unwrap();
    // Claims assigned to the proof
    assert_eq!(claims.first().unwrap().claim.value, "test");
}
