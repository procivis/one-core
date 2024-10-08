use axum::http::StatusCode;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use time::macros::format_description;
use time::OffsetDateTime;
use uuid::Uuid;

use super::full_flow_common::TestKey;
use crate::api_oidc_tests::full_flow_common::{ecdsa_key_1, eddsa_key_2, prepare_dids};
use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::interactions::SubmittedCredential;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_openid4vc_jwt_flow_eddsa_no_revocation() {
    test_openid4vc_jwt_flow(ecdsa_key_1(), eddsa_key_2(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jwt_flow_eddsa_bitstring_revocation() {
    test_openid4vc_jwt_flow(ecdsa_key_1(), eddsa_key_2(), "BITSTRINGSTATUSLIST").await
}

#[tokio::test]
async fn test_openid4vc_jwt_flow_eddsa_lvvc_revocation() {
    test_openid4vc_jwt_flow(ecdsa_key_1(), eddsa_key_2(), "LVVC").await
}
#[tokio::test]
async fn test_openid4vc_jwt_flow_eddsa_array() {
    test_openid4vc_jwt_flow_array(ecdsa_key_1(), eddsa_key_2()).await
}

async fn test_openid4vc_jwt_flow(
    server_key: TestKey,
    holder_key: TestKey,
    revocation_method: &str,
) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(&format!("{}.test", interaction_id)).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, server_local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(server_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;

    let server_did = server_did.unwrap();
    let holder_did = holder_did.unwrap();
    let server_local_key = server_local_key.unwrap();

    let new_claim_schemas = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (Uuid::new_v4(), "root/Key", true, "STRING", false),
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
            "JWT",
            "schema_id",
        )
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            vec![CreateProofInputSchema::from((
                &new_claim_schemas[..1],
                &credential_schema,
            ))],
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");

    let interaction_data = serde_json::to_vec(&json!({
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction_id,
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
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
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            }]
        },
        "nonce": nonce,
        "pre_authorized_code_used": true,
        "access_token": format!("{}.test",interaction_id),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    }))
    .unwrap();

    let interaction = server_context
        .db
        .interactions
        .create(Some(interaction_id), &base_url, &interaction_data)
        .await;

    let _credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                key: Some(server_local_key.to_owned()),
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    let proof = server_context
        .db
        .proofs
        .create(
            None,
            &server_did,
            Some(&holder_did),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            server_local_key.clone(),
        )
        .await;

    let jwt = [
        &json!(
            {
            "alg": "EDDSA",
            "typ": "JWT",
            "kid": holder_did.did
        })
        .to_string(),
        r#"{"aud":"test123"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, "jwt_vc_json", &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        Some(holder_key),
        Some(server_key),
    )
    .await;

    let server_did = server_did.unwrap();
    let holder_did = holder_did.unwrap();
    let local_key = local_key.unwrap();

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
            "JWT",
            &credential_schema.schema_id,
        )
        .await;

    let holder_credential = holder_context
        .db
        .credentials
        .create(
            &holder_credential_schema,
            CredentialStateEnum::Accepted,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                credential: Some(credential_token),
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
            "client_id_scheme": "redirect_uri",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
        },
        "response_mode": "direct_post",
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction.id,
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
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
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
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
            &server_did,
            Some(&holder_did),
            None,
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&holder_interaction),
            local_key,
        )
        .await;

    // WHEN
    let resp = holder_context
        .api
        .interactions
        .presentation_submit(
            holder_interaction.id,
            holder_did.id,
            vec![SubmittedCredential {
                proof_input_id: "input_0".to_string(),
                credential_id: holder_credential.id,
                claims_ids: vec![new_claim_schemas[0].0],
            }],
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    assert_eq!(claims.len(), 1);
    assert_eq!(claims.first().unwrap().claim.value, "test");

    let holder_proof = holder_context.db.proofs.get(&holder_proof.id).await;
    let claims = holder_proof.claims.unwrap();
    // Claims assigned to the proof
    assert_eq!(claims.len(), 1);
    assert_eq!(claims.first().unwrap().claim.value, "test");
}

async fn test_openid4vc_jwt_flow_array(server_key: TestKey, holder_key: TestKey) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(&format!("{}.test", interaction_id)).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, server_local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(server_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;

    let server_did = server_did.unwrap();
    let holder_did = holder_did.unwrap();
    let server_local_key = server_local_key.unwrap();

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
            "NONE",
            &new_claim_schemas,
            "JWT",
            "schema_id",
        )
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            vec![CreateProofInputSchema::from((
                &new_claim_schemas[..1],
                &credential_schema,
            ))],
        )
        .await;

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");

    let interaction_data = serde_json::to_vec(&json!({
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction_id,
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
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
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            }]
        },
        "nonce": nonce,
        "pre_authorized_code_used": true,
        "access_token": format!("{}.test",interaction_id),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
    }))
    .unwrap();

    let interaction = server_context
        .db
        .interactions
        .create(Some(interaction_id), &base_url, &interaction_data)
        .await;

    let _credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                key: Some(server_local_key.to_owned()),
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![
                    //(new_claim_schemas[3].0, "root/object_array/0/field1", "FV11"), // Optional, not present
                    //(new_claim_schemas[4].0, "root/object_array/1/field2", "FV22"), // Optional, not present
                    //(new_claim_schemas[3].0, "root/object_array/3/field1", "FV41"), // Optional, not present
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

    let proof = server_context
        .db
        .proofs
        .create(
            None,
            &server_did,
            Some(&holder_did),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            server_local_key.clone(),
        )
        .await;

    let holder_did_value = holder_did.did;

    let jwt = [
        &json!(
            {
            "alg": "EDDSA",
            "typ": "JWT",
            "kid": holder_did_value
        })
        .to_string(),
        r#"{"aud":"test123"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, "jwt_vc_json", &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        Some(holder_key),
        Some(server_key),
    )
    .await;

    let server_did = server_did.unwrap();
    let holder_did = holder_did.unwrap();
    let local_key = local_key.unwrap();

    let schema_id = Uuid::new_v4();
    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &holder_organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
            &credential_schema.schema_id,
        )
        .await;

    let holder_credential = holder_context
        .db
        .credentials
        .create(
            &holder_credential_schema,
            CredentialStateEnum::Accepted,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                credential: Some(credential_token),
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
            "client_id_scheme": "redirect_uri",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
        },
        "response_mode": "direct_post",
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction.id,
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
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
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
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
            &server_did,
            Some(&holder_did),
            None,
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&holder_interaction),
            local_key,
        )
        .await;

    // WHEN
    let resp = holder_context
        .api
        .interactions
        .presentation_submit(
            holder_interaction.id,
            holder_did.id,
            vec![SubmittedCredential {
                proof_input_id: "input_0".to_string(),
                credential_id: holder_credential.id,
                claims_ids: vec![new_claim_schemas[0].0],
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
