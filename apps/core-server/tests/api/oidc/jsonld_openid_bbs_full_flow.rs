use axum::http::StatusCode;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::proof::{ProofClaim, ProofStateEnum};
use serde_json::json;
use uuid::Uuid;

use crate::api_oidc_tests::full_flow_common::{
    bbs_key_1, ecdsa_key_1, eddsa_key_1, eddsa_key_2, get_array_context,
    get_simple_context_bbsplus, prepare_dids,
};
use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::interactions::SubmittedCredential;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_none() {
    test_openid4vc_jsonld_bbsplus_flow("NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_bitstring() {
    test_openid4vc_jsonld_bbsplus_flow("BITSTRINGSTATUSLIST").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_lvvc() {
    test_openid4vc_jsonld_bbsplus_flow("LVVC").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_array() {
    test_openid4vc_jsonld_bbsplus_array("NONE").await
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

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "Key 1", true, "STRING", false),
        (Uuid::new_v4(), "USCIS#", true, "STRING", false),
        (Uuid::new_v4(), "Address root", true, "OBJECT", false),
        (
            Uuid::new_v4(),
            "Address root/Address1",
            true,
            "STRING",
            false,
        ),
        (
            Uuid::new_v4(),
            "Address root/Address2",
            true,
            "STRING",
            false,
        ),
    ];

    let mut proof_claim_schemas = new_claim_schemas[..3].to_vec();
    proof_claim_schemas[0].2 = false; //Key is optional

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
            &format!("{base_url}/ssi/schema/v1/{schema_id}"),
        )
        .await;

    server_context
        .db
        .json_ld_contexts
        .prepare_cache(&[get_simple_context_bbsplus(
            &credential_schema.id,
            "Test",
            &base_url,
        )])
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
                random_claims: true,
                ..Default::default()
            },
        )
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            vec![CreateProofInputSchema::from((
                &proof_claim_schemas[..],
                &credential_schema,
            ))],
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
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.USCIS#"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.Address root"],
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
    holder_context
        .db
        .json_ld_contexts
        .prepare_cache(&[get_simple_context_bbsplus(
            &credential_schema.id,
            "Test",
            &base_url,
        )])
        .await;

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

    let holder_schema_id = Uuid::new_v4();
    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &holder_schema_id,
            "Test",
            &holder_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_BBSPLUS",
            &format!("{base_url}/ssi/schema/v1/{schema_id}"),
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
                random_claims: true,
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

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
                        // Disclose the whole address and special character claim
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.USCIS#"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.Address root"],
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
            vec![SubmittedCredential {
                proof_input_id: "input_0".to_string(),
                credential_id: holder_credential.id,
                claims_ids: vec![new_claim_schemas[1].0, new_claim_schemas[2].0],
            }],
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
    // Key was not disclosed
    assert!(!claims
        .iter()
        .any(|c| c.claim.schema.as_ref().unwrap().key == "Key 1"));

    assert!(claims
        .iter()
        .find(|c| c.claim.schema.as_ref().unwrap().key == "USCIS#")
        .unwrap()
        .claim
        .value
        .starts_with("test"));

    assert!(claims
        .iter()
        .find(|c| c.claim.schema.as_ref().unwrap().key == "Address root/Address1")
        .unwrap()
        .claim
        .value
        .starts_with("test"));

    assert!(claims
        .iter()
        .find(|c| c.claim.schema.as_ref().unwrap().key == "Address root/Address2")
        .unwrap()
        .claim
        .value
        .starts_with("test"));
}

async fn test_openid4vc_jsonld_bbsplus_array(revocation_method: &str) {
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

    let new_claim_schemas = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (Uuid::new_v4(), "root/array", true, "STRING", true),
        (Uuid::new_v4(), "root/object_array", true, "OBJECT", true),
        (
            Uuid::new_v4(),
            "root/object_array/field1",
            false,
            "STRING",
            false,
        ),
        (
            Uuid::new_v4(),
            "root/object_array/field2",
            false,
            "STRING",
            false,
        ),
    ];

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
            &format!("{base_url}/ssi/schema/v1/{schema_id}"),
        )
        .await;

    server_context
        .db
        .json_ld_contexts
        .prepare_cache(&[get_array_context(&credential_schema.id, "Test", &base_url)])
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
                claims_data: Some(vec![
                    // Keep random order
                    (new_claim_schemas[3].0, "root/object_array/1/field1", "FV21"),
                    (new_claim_schemas[1].0, "root/array/0", "Value1"),
                    (new_claim_schemas[4].0, "root/object_array/3/field2", "FV42"),
                    (new_claim_schemas[1].0, "root/array/2", "Value3"),
                    (new_claim_schemas[4].0, "root/object_array/0/field2", "FV12"),
                    (new_claim_schemas[3].0, "root/object_array/2/field1", "FV31"),
                    (new_claim_schemas[1].0, "root/array/1", "Value2"),
                    (new_claim_schemas[4].0, "root/object_array/2/field2", "FV32"),
                ]),
                ..Default::default()
            },
        )
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            vec![CreateProofInputSchema::from((
                &new_claim_schemas[1..=2],
                &credential_schema,
            ))],
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
                            "id": new_claim_schemas[1].0,
                            "path": [format!("$.vc.credentialSubject.root/array")],
                            "optional": false,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": [format!("$.vc.credentialSubject.root/object_array")],
                            "optional": false,
                            "intent_to_retain": true
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

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;
    holder_context
        .db
        .json_ld_contexts
        .prepare_cache(&[get_array_context(&credential_schema.id, "Test", &base_url)])
        .await;

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

    let holder_schema_id = Uuid::new_v4();
    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &holder_schema_id,
            "Test",
            &holder_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_BBSPLUS",
            &format!("{base_url}/ssi/schema/v1/{schema_id}"),
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
                claims_data: Some(vec![
                    // Keep random order
                    (new_claim_schemas[3].0, "root/object_array/1/field1", "FV21"),
                    (new_claim_schemas[1].0, "root/array/0", "Value1"),
                    (new_claim_schemas[4].0, "root/object_array/3/field2", "FV42"),
                    (new_claim_schemas[1].0, "root/array/2", "Value3"),
                    (new_claim_schemas[4].0, "root/object_array/0/field2", "FV12"),
                    (new_claim_schemas[3].0, "root/object_array/2/field1", "FV31"),
                    (new_claim_schemas[1].0, "root/array/1", "Value2"),
                    (new_claim_schemas[4].0, "root/object_array/2/field2", "FV32"),
                ]),
                ..Default::default()
            },
        )
        .await;

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
                        // Disclose the whole address
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.root/array"],
                            "optional": false,
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.root/object_array"],
                            "optional": false,
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

    let _ = holder_context
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
            vec![SubmittedCredential {
                proof_input_id: "input_0".to_string(),
                credential_id: holder_credential.id,
                claims_ids: vec![new_claim_schemas[1].0, new_claim_schemas[2].0],
            }],
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    assert_eq!(claims[0].claim.path, "root/array/0");
    assert_eq!(claims[0].claim.value, "Value1");
    assert_eq!(claims[1].claim.path, "root/array/1");
    assert_eq!(claims[1].claim.value, "Value2");
    assert_eq!(claims[2].claim.path, "root/array/2");
    assert_eq!(claims[2].claim.value, "Value3");

    assert_eq!(claims[3].claim.path, "root/object_array/0/field2");
    assert_eq!(claims[3].claim.value, "FV12");

    assert_eq!(claims[4].claim.path, "root/object_array/1/field1");
    assert_eq!(claims[4].claim.value, "FV21");

    assert_eq!(claims[5].claim.path, "root/object_array/2/field1");
    assert_eq!(claims[5].claim.value, "FV31");
    assert_eq!(claims[6].claim.path, "root/object_array/2/field2");
    assert_eq!(claims[6].claim.value, "FV32");

    assert_eq!(claims[7].claim.path, "root/object_array/3/field2");
    assert_eq!(claims[7].claim.value, "FV42");
}

#[tokio::test]
async fn test_opeind4vc_jsondl_only_bbs_supported() {
    // GIVEN
    let issuer_not_bbs_key = ecdsa_key_1();
    let holder_key = eddsa_key_1();

    let server_context = TestContext::new().await;
    let server_organisation = server_context.db.organisations.create().await;
    server_context.db.json_ld_contexts.prepare_cache(&[]).await;

    let (server_issuer_did, holder_did, server_issuer_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(issuer_not_bbs_key),
        Some(holder_key),
    )
    .await;
    let holder_did = holder_did.unwrap();

    let new_claim_schemas = vec![(Uuid::new_v4(), "Key", true, "STRING", false)];

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

    let resp = server_context
        .api
        .ssi
        .temporary_submit(credential.id, holder_did.did)
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
