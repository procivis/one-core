use std::str::FromStr;

use axum::http::StatusCode;
use one_core::model::{
    credential::CredentialStateEnum,
    did::{Did, DidType, KeyRole, RelatedKey},
    key::Key,
    organisation::Organisation,
    proof::ProofStateEnum,
};
use serde_json::json;
use shared_types::DidValue;
use uuid::Uuid;

use crate::{
    fixtures::{TestingCredentialParams, TestingDidParams, TestingKeyParams},
    utils::{context::TestContext, db_clients::proof_schemas::CreateProofInputSchema},
};

#[tokio::test]
async fn test_openid4vc_jsonld_flow_eddsa_eddsa() {
    test_openid4vc_jsonld_flow(eddsa_key_1(), eddsa_key_2(), "NONE").await
}

#[tokio::test]
async fn test_openid4vc_jsonld_flow_ecdsa_eddsa() {
    test_openid4vc_jsonld_flow(ecdsa_key_1(), eddsa_key_1(), "NONE").await
}

//Todo (ONE-1968): This works, but running too many tests at once will cause 429 Too Many Requests from w3.org
#[ignore]
#[tokio::test]
async fn test_openid4vc_jsonld_flow_eddsa_ecdsa() {
    test_openid4vc_jsonld_flow(eddsa_key_1(), ecdsa_key_1(), "NONE").await
}

// Todo (ONE-1968): This works, but running too many tests at once will cause 429 Too Many Requests from w3.org
#[ignore]
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

    let (server_did, holder_did, local_key) = prepare_dids(
        &server_context,
        &server_organisation,
        server_key.to_owned(),
        holder_key.to_owned(),
    )
    .await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str)> =
        vec![(Uuid::new_v4(), "Key", true, "STRING")];

    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            "Test",
            &server_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
        )
        .await;

    let credential = server_context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Offered,
            &server_did,
            "PROCIVIS_TEMPORARY",
            TestingCredentialParams {
                holder_did: Some(holder_did.clone()),
                key: Some(local_key.to_owned()),
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
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.credentialSubject.Key"],
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
            &server_did,
            Some(&holder_did),
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
            local_key,
        )
        .await;

    let resp = server_context
        .api
        .ssi
        .temporary_submit(credential.id, holder_did.id)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credentials = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids(
        &holder_context,
        &holder_organisation,
        holder_key,
        server_key,
    )
    .await;

    let holder_credential_schema = holder_context
        .db
        .credential_schemas
        .create_with_claims(
            "Test",
            &holder_organisation,
            revocation_method,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
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
                }
            },
            "client_id_scheme": "redirect_uri"
        },
        "response_mode": "direct_post",
        "response_uri": format!("{base_url}/ssi/oidc-verifier/v1/response"),
        "presentation_definition": {
            "id": interaction.id,
            "input_descriptors": [{
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": claims.first().unwrap().id,
                            "path": ["$.credentialSubject.Key"],
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

async fn prepare_dids(
    context: &TestContext,
    organisation: &Organisation,
    local_key_params: TestKey,
    remote_key_params: TestKey,
) -> (Did, Did, Key) {
    let local_key = context
        .db
        .keys
        .create(organisation, local_key_params.params)
        .await;
    let local_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Local),
                ..key_to_did_params(Some(&local_key), &local_key_params.multibase)
            },
        )
        .await;

    let remote_did = context
        .db
        .dids
        .create(
            organisation,
            TestingDidParams {
                did_type: Some(DidType::Remote),
                ..key_to_did_params(None, &remote_key_params.multibase)
            },
        )
        .await;
    (local_did, remote_did, local_key)
}

fn key_to_did_params(key: Option<&Key>, multibase: &str) -> TestingDidParams {
    TestingDidParams {
        did_method: Some("KEY".to_string()),
        did: Some(DidValue::from_str(&format!("did:key:{multibase}",)).unwrap()),
        keys: key.map(|key| {
            vec![
                RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: key.clone(),
                },
                RelatedKey {
                    role: KeyRole::Authentication,
                    key: key.clone(),
                },
            ]
        }),
        ..Default::default()
    }
}

#[derive(Clone)]
struct TestKey {
    multibase: String,
    params: TestingKeyParams,
}

fn eddsa_key_1() -> TestKey {
    TestKey {
        multibase: "z6Mkw6BZWh2yCJW3HJ9RuJfuFdSzmzRbgWgbzLnfahzZ3ZBB".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                247, 48, 105, 26, 32, 134, 117, 181, 204, 194, 200, 75, 150, 16, 179, 22, 25, 85,
                252, 36, 83, 75, 3, 227, 191, 61, 55, 14, 149, 78, 206, 62,
            ]),
            key_reference: Some(vec![
                212, 80, 75, 28, 149, 144, 224, 28, 223, 35, 146, 169, 0, 0, 0, 0, 0, 0, 0, 64, 68,
                141, 148, 184, 183, 93, 124, 94, 83, 37, 210, 158, 29, 198, 205, 80, 195, 231, 51,
                105, 223, 240, 42, 129, 38, 242, 34, 135, 183, 137, 16, 97, 99, 78, 128, 164, 7,
                224, 218, 192, 165, 238, 164, 235, 194, 174, 23, 8, 65, 236, 151, 160, 239, 122,
                128, 137, 179, 207, 221, 144, 39, 35, 41, 197, 187, 16, 201, 230, 68, 12, 227, 117,
                56, 166, 196, 208, 5, 218, 2, 154,
            ]),
            ..Default::default()
        },
    }
}

fn eddsa_key_2() -> TestKey {
    TestKey {
        multibase: "z6Mki2njTKAL6rctJpMzHEeL35qhnG1wQaTG2knLVSk93Bj5".to_string(),
        params: TestingKeyParams {
            key_type: Some("EDDSA".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                53, 41, 236, 251, 185, 9, 201, 18, 100, 252, 20, 153, 131, 142, 218, 73, 109, 237,
                68, 35, 207, 20, 15, 39, 108, 188, 153, 46, 114, 75, 86, 224,
            ]),
            key_reference: Some(vec![
                103, 220, 116, 52, 196, 76, 31, 218, 7, 98, 15, 113, 0, 0, 0, 0, 0, 0, 0, 64, 24,
                146, 78, 36, 166, 76, 92, 244, 62, 141, 72, 168, 119, 97, 65, 237, 225, 64, 143,
                194, 12, 54, 139, 194, 174, 4, 166, 254, 120, 85, 50, 195, 244, 114, 34, 66, 225,
                119, 93, 162, 209, 171, 21, 33, 239, 46, 38, 225, 251, 115, 125, 119, 103, 172, 90,
                0, 57, 203, 39, 186, 177, 154, 133, 61, 38, 126, 230, 178, 135, 149, 20, 28, 80,
                208, 0, 205, 166, 10, 225, 50,
            ]),
            ..Default::default()
        },
    }
}

fn ecdsa_key_1() -> TestKey {
    TestKey {
        multibase: "zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6".to_string(),
        params: TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20, 151,
                189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
            ]),
            key_reference: Some(vec![
                214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0, 0, 32,
                168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166, 110, 17, 207, 54,
                243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122, 234, 133, 236, 18, 64,
                113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54, 210, 76,
            ]),
            ..Default::default()
        },
    }
}

fn ecdsa_key_2() -> TestKey {
    TestKey {
        multibase: "zDnaeY6V3KGKLzgK3C2hbb4zMpeVKbrtWhEP4WXUyTAbshioQ".to_string(),
        params: TestingKeyParams {
            key_type: Some("ES256".to_string()),
            storage_type: Some("INTERNAL".to_string()),
            public_key: Some(vec![
                2, 113, 223, 203, 78, 208, 144, 157, 171, 118, 94, 112, 196, 150, 233, 175, 129, 0,
                12, 229, 151, 39, 80, 197, 83, 144, 248, 160, 227, 159, 2, 215, 39,
            ]),
            key_reference: Some(vec![
                191, 117, 227, 19, 61, 61, 70, 152, 133, 158, 83, 244, 0, 0, 0, 0, 0, 0, 0, 32, 1,
                0, 223, 243, 57, 200, 101, 206, 133, 43, 169, 194, 153, 38, 105, 35, 100, 79, 106,
                61, 68, 62, 9, 96, 48, 202, 28, 74, 43, 89, 96, 100, 154, 148, 140, 180, 17, 135,
                78, 216, 169, 229, 27, 196, 181, 163, 95, 116,
            ]),
            ..Default::default()
        },
    }
}
