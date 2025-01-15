use axum::http::StatusCode;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::credential::CredentialStateEnum;
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use time::macros::format_description;
use time::OffsetDateTime;
use uuid::Uuid;

use super::full_flow_common::{eddsa_key_1, eddsa_key_for_did_mdl, prepare_dids_for_mdoc};
use crate::api_oidc_tests::full_flow_common::{ecdsa_key_1, eddsa_key_2, prepare_dids};
use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::interactions::SubmittedCredential;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_openid4vc_jwt_mdoc_flow() {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context =
        TestContext::new_with_token(&format!("{}.test", interaction_id), None).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let server_key = ecdsa_key_1();
    let server_mdoc_key = eddsa_key_for_did_mdl();
    let holder_key = eddsa_key_1();

    let (server_did, holder_did, server_local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        Some(server_key.to_owned()),
        Some(holder_key.to_owned()),
    )
    .await;
    let (server_mdoc_did, _, server_mdoc_local_key) = prepare_dids_for_mdoc(
        &server_context,
        &server_organisation,
        server_mdoc_key.to_owned(),
        eddsa_key_2(),
    )
    .await;

    let server_did = server_did.unwrap();
    let holder_did = holder_did.unwrap();
    let server_local_key = server_local_key.unwrap();

    let jwt_new_claim_schemas = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (Uuid::new_v4(), "root/Key", true, "STRING", false),
    ];
    let mdoc_new_claim_schemas = vec![
        (Uuid::new_v4(), "obj", true, "OBJECT", false),
        (Uuid::new_v4(), "obj/name", true, "STRING", false),
    ];

    let jwt_schema_id = Uuid::new_v4();
    let jwt_credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &jwt_schema_id,
            "Test_jwt",
            &server_organisation,
            "NONE",
            &jwt_new_claim_schemas,
            "JWT",
            "schema_id",
        )
        .await;

    let mdoc_schema_id = Uuid::new_v4();
    let doctype = "org.iso.23220.1.mID";
    let mdoc_credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &mdoc_schema_id,
            "Test_mdoc",
            &server_organisation,
            "NONE",
            &mdoc_new_claim_schemas,
            "MDOC",
            doctype,
        )
        .await;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
            vec![
                CreateProofInputSchema::from((&jwt_new_claim_schemas[..1], &jwt_credential_schema)),
                CreateProofInputSchema::from((
                    &mdoc_new_claim_schemas[1..2],
                    &mdoc_credential_schema,
                )),
            ],
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
                                "const": jwt_credential_schema.schema_id
                            }
                        },
                        {
                            "id": jwt_new_claim_schemas[0].0,
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            },
            {
                "format": {
                    "mso_mdoc": {
                        "proof_type": [
                            "DataIntegrityProof"
                        ]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": mdoc_credential_schema.schema_id
                            }
                        },
                        {
                            "id": jwt_new_claim_schemas[1].0,
                            "path": ["$['obj']['name']"],
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
        .create(
            Some(interaction_id),
            &base_url,
            &interaction_data,
            &server_organisation,
        )
        .await;

    let _credential = server_context
        .db
        .credentials
        .create(
            &jwt_credential_schema,
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
    let _credential = server_context
        .db
        .credentials
        .create(
            &mdoc_credential_schema,
            CredentialStateEnum::Offered,
            &server_mdoc_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                key: Some(server_mdoc_local_key.to_owned()),
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

    let jwt_mdoc = [
        &json!(
            {
            "alg": "EDDSA",
            "typ": "JWT",
            "kid": holder_did_value
        })
        .to_string(),
        r#"{"aud":"test456"}"#,
        "MissingSignature",
    ]
    .map(|s| Base64UrlSafeNoPadding::encode_to_string(s).unwrap())
    .join(".");

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential(jwt_credential_schema.id, "jwt_vc_json", &jwt)
        .await;
    assert_eq!(resp.status(), 200);
    let resp_jwt = resp.json_value().await;

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential_mdoc(mdoc_credential_schema.id, doctype, &jwt_mdoc)
        .await;
    assert_eq!(resp.status(), 200);
    let resp_mdoc = resp.json_value().await;

    // Valid credentials
    let jwt_token = resp_jwt["credential"].as_str().unwrap();
    let mdoc_token = resp_mdoc["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new(None).await;
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

    let jwt_schema_id = Uuid::new_v4();
    let mdoc_schema_id = Uuid::new_v4();

    let holder_jwt_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &jwt_schema_id,
            "Test_jwt",
            &holder_organisation,
            "NONE",
            &jwt_new_claim_schemas,
            "JWT",
            &jwt_credential_schema.schema_id,
        )
        .await;
    let holder_mdoc_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            &mdoc_schema_id,
            "Test_mdoc",
            &holder_organisation,
            "NONE",
            &mdoc_new_claim_schemas,
            "MDOC",
            &mdoc_credential_schema.schema_id,
        )
        .await;

    let holder_jwt_credential = holder_context
        .db
        .credentials
        .create(
            &holder_jwt_credential_schema,
            CredentialStateEnum::Accepted,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                credential: Some(jwt_token),
                ..Default::default()
            },
        )
        .await;
    let holder_mdoc_credential = holder_context
        .db
        .credentials
        .create(
            &holder_mdoc_credential_schema,
            CredentialStateEnum::Accepted,
            &server_did,
            "OPENID4VC",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                credential: Some(mdoc_token),
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
                                "const": jwt_credential_schema.schema_id
                            }
                        },
                        {
                            "id": jwt_new_claim_schemas[0].0,
                            "path": [format!("$.vc.credentialSubject.root")],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            },
            {
                "format": {
                    "mso_mdoc": {
                        "proof_type": [
                            "DataIntegrityProof"
                        ]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": mdoc_credential_schema.schema_id
                            }
                        },
                        {
                            "id": mdoc_new_claim_schemas[1].0,
                            "path": ["$['obj']['name']"],
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
            &holder_organisation,
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
            ProofStateEnum::Requested,
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
            vec![
                SubmittedCredential {
                    proof_input_id: "input_0".to_string(),
                    credential_id: holder_jwt_credential.id,
                    claims_ids: vec![jwt_new_claim_schemas[0].0],
                },
                SubmittedCredential {
                    proof_input_id: "input_1".to_string(),
                    credential_id: holder_mdoc_credential.id,
                    claims_ids: vec![mdoc_new_claim_schemas[1].0],
                },
            ],
        )
        .await;

    // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].claim.value, "test");
    assert_eq!(claims[1].claim.value, "test");

    let holder_proof = holder_context.db.proofs.get(&holder_proof.id).await;
    let claims = holder_proof.claims.unwrap();
    // Claims assigned to the proof
    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].claim.value, "test");
    assert_eq!(claims[1].claim.value, "test");
}
