use axum::http::StatusCode;
use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchemaType;
use one_core::model::proof::ProofStateEnum;
use one_crypto::hasher::sha256::SHA256;
use one_crypto::Hasher;
use serde_json::json;
use time::macros::format_description;
use time::OffsetDateTime;
use uuid::Uuid;

use super::full_flow_common::TestKey;
use crate::api_oidc_tests::full_flow_common::{
    ecdsa_key_1, eddsa_key_2, prepare_dids, proof_jwt_for,
};
use crate::fixtures::TestingCredentialParams;
use crate::utils::api_clients::interactions::SubmittedCredential;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_openid4vc_sdjwt_vc_flow_external_schema() {
    test_openid4vc_sdjwt_vc_flow(ecdsa_key_1(), eddsa_key_2(), "NONE").await
}

async fn test_openid4vc_sdjwt_vc_flow(
    server_key: TestKey,
    holder_key: TestKey,
    revocation_method: &str,
) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context =
        TestContext::new_with_token(&format!("{}.test", interaction_id), None).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;

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

    let nonce = "nonce123";
    const VCT: &str = "test.vct.value";

    let credential_schema = server_context
        .db
        .credential_schemas
        .create(
            "Test External Sd-jwt-vc",
            &server_organisation,
            revocation_method,
            TestingCreateSchemaParams {
                external_schema: true,
                schema_id: Some(VCT.to_string()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                format: Some("SD_JWT_VC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = server_context
        .db
        .proof_schemas
        .create(
            "Test",
            &server_organisation,
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

    let date_format =
        format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond]Z");

    let interaction_data = serde_json::to_vec(&json!({
        "client_id_scheme": "redirect_uri",
        "client_id": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction_id,
            "input_descriptors": [{
                "format": {
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256K"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256K"]
                    }
                },
                "id": "input_0",
                "vct": VCT,
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema.schema_id
                            }
                        },
                        {
                            "id": claim_schema.id,
                            "path": ["$.firstName"],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            }]
        },
        "nonce": nonce,
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(format!("{}.test", interaction_id).as_bytes()).unwrap(),
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

    let holder_key_id = "did:key:z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5#z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5";
    let jwt = proof_jwt_for(&holder_key, holder_key_id).await;

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

    let resp = server_context
        .api
        .ssi
        .issuer_create_credential(credential_schema.id, "vc+sd-jwt", &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

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

    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create(
            "Test External Sd-jwt-vc",
            &holder_organisation,
            revocation_method,
            TestingCreateSchemaParams {
                external_schema: true,
                schema_id: Some(VCT.to_string()),
                schema_type: Some(CredentialSchemaType::SdJwtVc),
                format: Some("SD_JWT_VC".to_string()),
                ..Default::default()
            },
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
                key: Some(local_key.to_owned()),
                ..Default::default()
            },
        )
        .await;

    let claim_schema = &holder_credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let holder_interaction_data = json!({
        "response_type": "vp_token",
        "state": interaction.id,
        "nonce": nonce,
        "client_id_scheme": "redirect_uri",
        "client_id": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "client_metadata": {
            "vp_formats": {
                "vc+sd-jwt": {
                    "kb-jwt_alg_values": ["EdDSA", "ES256K"],
                    "sd-jwt_alg_values": ["EdDSA", "ES256K"]
                },
            },
            "client_id_scheme": "redirect_uri",
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A256GCM"
        },
        "presentation_definition": {
            "id": interaction.id,
            "input_descriptors": [{
                "format": {
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256K"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256K"]
                    }
                },
                "id": "input_0",
                "vct": VCT,
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.vct"],
                            "filter": {
                                "type": "string",
                                "const": VCT
                            }
                        },
                        {
                            "id": claim_schema.id,
                            "path": [format!("$.{}", claim_schema.key)],
                            "optional": false,
                            "intent_to_retain": true
                        }
                    ]
                }
            }]
        },
        "pre_authorized_code_used": true,
        "access_token_hash": SHA256.hash(format!("{}.test", interaction_id).as_bytes()).unwrap(),
        "access_token_expires_at": (OffsetDateTime::now_utc() + time::Duration::seconds(20)).format(&date_format).unwrap(),
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

    let resp = holder_context
        .api
        .interactions
        .presentation_submit(
            holder_interaction.id,
            holder_did.id,
            vec![SubmittedCredential {
                proof_input_id: "input_0".to_string(),
                credential_id: holder_credential.id,
                claims_ids: vec![claim_schema.id.into()],
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
