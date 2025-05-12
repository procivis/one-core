use axum::http::StatusCode;
use one_core::config::core_config::VerificationProtocolType;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::proof::{ProofClaim, ProofStateEnum};
use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use serde_json::json;
use time::OffsetDateTime;
use time::macros::format_description;
use uuid::Uuid;

use crate::api_oidc_tests::full_flow_common::{
    bbs_key_1, eddsa_key_1, eddsa_key_2, get_simple_context_bbsplus, prepare_dids, proof_jwt_for,
};
use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::interactions::SubmittedCredential;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_bitstring_json_ld_classic_openid4vp_draft20() {
    let additional_config = r#"revocation:
  BITSTRINGSTATUSLIST:
    params:
      public:
        format: 'JSON_LD_CLASSIC'"#
        .to_string();
    test_openid4vc_jsonld_bbsplus_flow(
        "BITSTRINGSTATUSLIST",
        VerificationProtocolType::OpenId4VpDraft20,
        Some(additional_config),
    )
    .await
}

#[tokio::test]
async fn test_openid4vc_jsonld_bbsplus_flow_bitstring_json_ld_classic_openid4vp_draft25() {
    let additional_config = r#"revocation:
  BITSTRINGSTATUSLIST:
    params:
      public:
        format: 'JSON_LD_CLASSIC'"#
        .to_string();
    test_openid4vc_jsonld_bbsplus_flow(
        "BITSTRINGSTATUSLIST",
        VerificationProtocolType::OpenId4VpDraft25,
        Some(additional_config),
    )
    .await
}

async fn test_openid4vc_jsonld_bbsplus_flow(
    revocation_method: &str,
    verification_protocol: VerificationProtocolType,
    additional_config: Option<String>,
) {
    // GIVEN
    let issuer_bbs_key = bbs_key_1();
    let holder_key = eddsa_key_1();
    let verifier_key = eddsa_key_2();

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(
        &format!("{}.test", interaction_id),
        additional_config.clone(),
    )
    .await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_issuer, _, server_issuer_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(issuer_bbs_key.to_owned()),
        None,
    )
    .await;

    let (_, server_issuer_identifier) = server_issuer.unwrap();

    let (verifier, holder, local_verifier_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(verifier_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;

    let (server_remote_holder_did, server_remote_holder_identifier) = holder.unwrap();
    let (server_local_verifier_did, server_local_verifier_identifier) = verifier.unwrap();
    let server_local_verifier_key = local_verifier_key.unwrap();

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "TestSubject/Key 1", true, "STRING", false),
        (Uuid::new_v4(), "TestSubject/USCIS#", true, "STRING", false),
        (
            Uuid::new_v4(),
            "TestSubject/Address root",
            true,
            "OBJECT",
            false,
        ),
        (
            Uuid::new_v4(),
            "TestSubject/Address root/Address1",
            true,
            "STRING",
            false,
        ),
        (
            Uuid::new_v4(),
            "TestSubject/Address root/Address2",
            true,
            "STRING",
            false,
        ),
        (Uuid::new_v4(), "TestSubject", true, "OBJECT", false),
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
        .remote_entities
        .prepare_cache(&[get_simple_context_bbsplus(
            &credential_schema.id,
            "Test",
            &base_url,
        )])
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

    let credential_interaction_data = json!({
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(format!("{}.test",interaction_id).as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    });

    let credential_interaction = server_context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &base_url,
            credential_interaction_data.to_string().as_bytes(),
            &server_organisation,
        )
        .await;

    let _credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(server_remote_holder_identifier.clone()),
                key: Some(server_issuer_key.unwrap()),
                random_claims: true,
                interaction: Some(credential_interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    let interaction_id = Uuid::new_v4();
    let response_uri = match verification_protocol {
        VerificationProtocolType::OpenId4VpDraft20 => {
            format!("{base_url}/ssi/openid4vp/draft-20/response")
        }
        VerificationProtocolType::OpenId4VpDraft25 => {
            format!("{base_url}/ssi/openid4vp/draft-25/response")
        }
        _ => unreachable!(),
    };
    let proof_interaction_data = json!({
        "client_id_scheme": "redirect_uri",
        "client_id": response_uri,
        "response_uri": response_uri,
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
                            "path": ["$.vc.credentialSubject.TestSubject/USCIS#"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.TestSubject/Address root"],
                            "optional": false
                        }
                    ]
                }
            }]
        }
    });

    let proof_interaction = server_context
        .db
        .interactions
        .create(
            Some(interaction_id),
            &base_url,
            proof_interaction_data.to_string().as_bytes(),
            &server_organisation,
        )
        .await;

    let proof = server_context
        .db
        .proofs
        .create(
            None,
            &server_local_verifier_did,
            &server_local_verifier_identifier,
            Some(&server_remote_holder_did),
            Some(&server_remote_holder_identifier),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            verification_protocol.as_ref(),
            Some(&proof_interaction),
            server_local_verifier_key,
        )
        .await;

    let jwt = proof_jwt_for(
        &holder_key,
        Some(&server_remote_holder_did.did.to_string()),
        None,
    )
    .await;

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, "ldp_vc", &jwt, None)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credentials = resp["credential"].as_str();
    assert!(credentials.is_some());

    // Valid holder context
    let holder_context = TestContext::new(additional_config).await;
    let holder_organisation = holder_context.db.organisations.create().await;
    holder_context
        .db
        .remote_entities
        .prepare_cache(&[get_simple_context_bbsplus(
            &credential_schema.id,
            "Test",
            &base_url,
        )])
        .await;

    let (holder_local, verifier_remote, local_holer_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        Some(holder_key.to_owned()),
        Some(verifier_key.to_owned()),
    )
    .await;

    let (holder_local_holder_did, holder_local_holder_identifier) = holder_local.unwrap();
    let (holder_remote_verifier_did, holder_remote_verifier_identifier) = verifier_remote.unwrap();
    let holder_local_holer_key = local_holer_key.unwrap();

    let (_, remote_issuer, _) = prepare_dids(
        &holder_context,
        &holder_organisation,
        None,
        Some(issuer_bbs_key.to_owned()),
    )
    .await;

    let (_, holder_remote_issuer_identifier) = remote_issuer.unwrap();

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
            &holder_remote_issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_local_holder_identifier.clone()),
                credential: Some(credentials.unwrap()),
                random_claims: true,
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    let holder_interaction_data = json!({
        "response_type": "vp_token",
        "state": proof_interaction.id,
        "nonce": nonce,
        "client_id_scheme": "redirect_uri",
        "client_id": response_uri,
        "client_metadata": {
            "jwks": {
                "keys": [{
                    "crv": "P-256",
                    "kid": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
                    "kty": "EC",
                    "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                    "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                    "use": "enc"
                }]
            },
            "vp_formats": {
                "vc+sd-jwt": {
                    "kb-jwt_alg_values": ["EdDSA", "ES256"],
                    "sd-jwt_alg_values": ["EdDSA", "ES256"]
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
                "ldp_vp": {
                    "proof_type": [
                        "DataIntegrityProof"
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
        "response_uri": response_uri,
        "presentation_definition": {
            "id": proof_interaction.id,
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
                            "path": ["$.vc.credentialSubject.TestSubject/USCIS#"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": ["$.vc.credentialSubject.TestSubject/Address root"],
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
            &holder_organisation,
        )
        .await;

    let holder_proof = holder_context
        .db
        .proofs
        .create(
            Some(proof.id),
            &holder_remote_verifier_did,
            &holder_remote_verifier_identifier,
            Some(&holder_local_holder_did),
            Some(&holder_local_holder_identifier),
            None,
            ProofStateEnum::Requested,
            verification_protocol.as_ref(),
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
    assert!(
        !claims
            .iter()
            .any(|c| c.claim.schema.as_ref().unwrap().key == "TestSubject/Key 1")
    );

    assert!(
        claims
            .iter()
            .find(|c| c.claim.schema.as_ref().unwrap().key == "TestSubject/USCIS#")
            .unwrap()
            .claim
            .value
            .starts_with("test")
    );

    assert!(
        claims
            .iter()
            .find(|c| c.claim.schema.as_ref().unwrap().key == "TestSubject/Address root/Address1")
            .unwrap()
            .claim
            .value
            .starts_with("test")
    );

    assert!(
        claims
            .iter()
            .find(|c| c.claim.schema.as_ref().unwrap().key == "TestSubject/Address root/Address2")
            .unwrap()
            .claim
            .value
            .starts_with("test")
    );
}
