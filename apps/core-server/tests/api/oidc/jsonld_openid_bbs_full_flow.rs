use axum::http::StatusCode;
use one_core::model::{
    credential::CredentialStateEnum,
    proof::{ProofClaim, ProofStateEnum},
};
use serde_json::json;
use uuid::Uuid;

use crate::{
    api_oidc_tests::full_flow_common::{
        bbs_key_1, ecdsa_key_1, eddsa_key_1, eddsa_key_2, prepare_dids,
    },
    fixtures::TestingCredentialParams,
    utils::{context::TestContext, db_clients::proof_schemas::CreateProofInputSchema},
};

// Todo (ONE-1968): This works, but running too many tests at once will cause 429 Too Many Requests from w3.org
#[ignore]
#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_bitstring() {
    test_openid4vc_jsonld_bbsplus_flow("BITSTRINGSTATUSLIST").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_lvvc() {
    test_openid4vc_jsonld_bbsplus_flow("LVVC").await
}

async fn test_openid4vc_jsonld_bbsplus_flow(revocation_method: &str) {
    // GIVEN
    let issuer_bbs_key = bbs_key_1();
    let holder_key = eddsa_key_1();
    let verifier_key = eddsa_key_2();

    let server_context = TestContext::new().await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_issuer_did, _, server_issuer_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(issuer_bbs_key.to_owned()),
        None,
    )
    .await;

    let (verifier_did, holder_did, local_verifier_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(verifier_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;

    let server_remote_holder_did = holder_did.unwrap();
    let server_local_verifier_did = verifier_did.unwrap();
    let server_local_verifier_key = local_verifier_key.unwrap();

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> = vec![
        (Uuid::new_v4(), "Key", true, "STRING"),
        (Uuid::new_v4(), "Name", true, "STRING"),
        (Uuid::new_v4(), "Address", true, "STRING"),
    ];

    let mut proof_claim_schemas: Vec<(Uuid, &str, bool, &str)> = new_claim_schemas.clone();
    proof_claim_schemas[0].2 = false; //Key is optional
    proof_claim_schemas[2].2 = false; //Address is optional

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
            "JSON_LD_BBSPLUS",
            &schema_id.to_string(),
        )
        .await;

    let credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_issuer_did.unwrap(),
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: Some(server_remote_holder_did.clone()),
                key: Some(server_issuer_key.unwrap()),
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
            CreateProofInputSchema::from((&proof_claim_schemas[..], &credential_schema)),
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
                            "optional": true
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.Name"],
                            "optional": true
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.Address"],
                            "optional": true
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
            &server_local_verifier_did,
            Some(&server_remote_holder_did),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            server_local_verifier_key,
        )
        .await;

    let resp = server_context
        .api
        .ssi
        .temporary_submit(credential.id, server_remote_holder_did.did)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credentials = resp["credential"].as_str();
    assert!(credentials.is_some());

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_local_did, verifier_remote_did, local_holer_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        Some(holder_key.to_owned()),
        Some(verifier_key.to_owned()),
    )
    .await;

    let holder_local_holder_did = holder_local_did.unwrap();
    let holder_remote_verifier_did = verifier_remote_did.unwrap();
    let holder_local_holer_key = local_holer_key.unwrap();

    let (_, remote_issuer_did, _) = prepare_dids(
        &holder_context,
        &holder_organisation,
        None,
        Some(issuer_bbs_key.to_owned()),
    )
    .await;

    let holder_remote_issuer_did = remote_issuer_did.unwrap();

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
            // This reflects latest changes - on the holder side we don't really know what's the correct format here
            "JSON_LD",
            &credential_schema.schema_id,
        )
        .await;

    let holder_credential = holder_context
        .db
        .credentials
        .create(
            &holder_credential_schema,
            CredentialStateEnum::Accepted,
            &holder_remote_issuer_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_local_holder_did.clone()),
                credential: Some(credentials.unwrap()),
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
                        "EdDSA",
                        "BBS_PLUS"
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
                            "id": claims[1].id,
                            "path": ["$.vc.credentialSubject.Name"],
                            "optional": true
                        },
                        {
                            "id": claims[2].id,
                            "path": ["$.vc.credentialSubject.Address"],
                            "optional": true
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
            &holder_remote_verifier_did,
            Some(&holder_local_holder_did),
            None,
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&holder_interaction),
            holder_local_holer_key,
        )
        .await;

    // WHEN
    let resp = holder_context
        .api
        .interactions
        .presentation_submit(
            holder_interaction.id,
            holder_local_holder_did.id,
            holder_credential.id,
            claims,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    verify_claims(claims);

    let holder_proof = holder_context.db.proofs.get(&holder_proof.id).await;
    let claims = holder_proof.claims.unwrap();
    // Claims assigned to the proof
    verify_claims(claims);
}

fn verify_claims(claims: Vec<ProofClaim>) {
    assert!(
        claims
            .iter()
            .find(|c| c.claim.schema.as_ref().unwrap().key == "Name")
            .unwrap()
            .claim
            .value
            == "test"
    );

    assert!(
        claims
            .iter()
            .find(|c| c.claim.schema.as_ref().unwrap().key == "Address")
            .unwrap()
            .claim
            .value
            == "test"
    );

    assert!(!claims
        .iter()
        .any(|c| c.claim.schema.as_ref().unwrap().key == "Key"));
}

#[tokio::test]
async fn test_opeind4vc_jsondl_only_bbs_supported() {
    // GIVEN
    let issuer_not_bbs_key = ecdsa_key_1();
    let holder_key = eddsa_key_1();

    let server_context = TestContext::new().await;
    let server_organisation = server_context.db.organisations.create().await;

    let (server_issuer_did, holder_did, server_issuer_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(issuer_not_bbs_key),
        Some(holder_key),
    )
    .await;
    let holder_did = holder_did.unwrap();

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> =
        vec![(Uuid::new_v4(), "Key", true, "STRING")];

    let schema_id = Uuid::new_v4();

    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &server_organisation,
            "BITSTRINGSTATUSLIST",
            &new_claim_schemas,
            "JSON_LD_BBSPLUS",
            &schema_id.to_string(),
        )
        .await;

    let credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_issuer_did.unwrap(),
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                key: Some(server_issuer_key.unwrap()),
                ..Default::default()
            },
        )
        .await;

    server_context
        .server_mock
        .json_ld_context(&credential_schema.id, "Test")
        .await;

    let resp = server_context
        .api
        .ssi
        .temporary_submit(credential.id, holder_did.did)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
