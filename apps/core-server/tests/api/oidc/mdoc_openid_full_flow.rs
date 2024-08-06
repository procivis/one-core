use axum::http::StatusCode;
use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::model::{
    credential::CredentialStateEnum,
    proof::{ProofClaim, ProofStateEnum},
};
use one_providers::common_models::key::OpenKey;
use serde_json::json;

use uuid::Uuid;

use crate::{
    api_oidc_tests::full_flow_common::{
        ecdsa_key_2, eddsa_key_2, eddsa_key_for_did_mdl, es256_key_for_did_mdl,
        prepare_dids_for_mdoc,
    },
    fixtures::TestingCredentialParams,
    utils::{context::TestContext, db_clients::proof_schemas::CreateProofInputSchema},
};

use p256::elliptic_curve::sec1::ToEncodedPoint;

use time::{macros::format_description, OffsetDateTime};

use super::full_flow_common::TestKey;

enum KeyType {
    Ecdsa,
    Eddsa,
}

struct KeyData {
    pub x: String,
    pub y: Option<String>,
    pub kty: String,
    pub crv: String,
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_eddsa() {
    test_openid4vc_mdoc_flow(eddsa_key_for_did_mdl(), eddsa_key_2(), KeyType::Eddsa).await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_eddsa_ecdsa() {
    test_openid4vc_mdoc_flow(eddsa_key_for_did_mdl(), ecdsa_key_2(), KeyType::Eddsa).await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_ecdsa() {
    test_openid4vc_mdoc_flow(es256_key_for_did_mdl(), ecdsa_key_2(), KeyType::Ecdsa).await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_ecdsa_eddsa() {
    test_openid4vc_mdoc_flow(es256_key_for_did_mdl(), eddsa_key_2(), KeyType::Ecdsa).await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_eddsa_selective() {
    test_openid4vc_mdoc_flow_selective_nested_multiple_namespaces(
        eddsa_key_for_did_mdl(),
        eddsa_key_2(),
        KeyType::Eddsa,
    )
    .await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_ecdsa_selective() {
    test_openid4vc_mdoc_flow_selective_nested_multiple_namespaces(
        es256_key_for_did_mdl(),
        ecdsa_key_2(),
        KeyType::Ecdsa,
    )
    .await
}

#[tokio::test]
async fn test_openid4vc_mdoc_flow_ecdsa_array() {
    test_openid4vc_mdoc_flow_array(es256_key_for_did_mdl(), ecdsa_key_2(), KeyType::Ecdsa).await
}

fn get_key_data(key_type: KeyType, key: OpenKey) -> KeyData {
    match key_type {
        KeyType::Ecdsa => {
            let pk = p256::PublicKey::from_sec1_bytes(&key.public_key).unwrap();

            let encoded_point = pk.to_encoded_point(false);

            let x = Base64UrlSafeNoPadding::encode_to_string(encoded_point.x().unwrap()).unwrap();
            let y = Base64UrlSafeNoPadding::encode_to_string(encoded_point.y().unwrap()).unwrap();

            KeyData {
                x,
                y: Some(y),
                kty: "EC".to_owned(),
                crv: "P-256".to_owned(),
            }
        }
        KeyType::Eddsa => {
            let x = Base64UrlSafeNoPadding::encode_to_string(&key.public_key).unwrap();

            KeyData {
                x,
                y: None,
                kty: "OKP".to_owned(),
                crv: "Ed25519".to_owned(),
            }
        }
    }
}

async fn test_openid4vc_mdoc_flow(
    server_key: TestKey,
    holder_key: TestKey,
    issuer_key_type: KeyType,
) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(&format!("{}.test", interaction_id)).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, server_local_key) = prepare_dids_for_mdoc(
        &server_context,
        &server_organisation,
        server_key.to_owned(),
        holder_key.to_owned(),
    )
    .await;

    let key_data = get_key_data(issuer_key_type, server_local_key.clone());

    let new_claim_schemas = vec![
        (Uuid::new_v4(), "root", true, "OBJECT", false),
        (Uuid::new_v4(), "root/Key", true, "STRING", false),
    ];

    let schema_id = Uuid::new_v4();
    let doctype = "org.iso.23220.1.mID";
    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &server_organisation,
            "NONE",
            &new_claim_schemas,
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
            CreateProofInputSchema::from((&new_claim_schemas[1..2], &credential_schema)),
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['Key']")],
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
        .issuer_create_credential_mdoc(credential_schema.id, doctype, &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids_for_mdoc(
        &holder_context,
        &holder_organisation,
        holder_key,
        server_key,
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
            "NONE",
            &new_claim_schemas,
            "MDOC",
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
                    "crv": key_data.crv,
                    "kid": server_local_key.id.to_string(),
                    "kty": key_data.kty,
                    "x": key_data.x,
                    "y": key_data.y,
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['Key']")],
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
            holder_credential.id,
            vec![new_claim_schemas[1].0],
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

async fn test_openid4vc_mdoc_flow_selective_nested_multiple_namespaces(
    server_key: TestKey,
    holder_key: TestKey,
    issuer_key_type: KeyType,
) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(&format!("{}.test", interaction_id)).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, server_local_key) = prepare_dids_for_mdoc(
        &server_context,
        &server_organisation,
        server_key.to_owned(),
        holder_key.to_owned(),
    )
    .await;

    let key_data = get_key_data(issuer_key_type, server_local_key.clone());

    let new_claim_schemas = vec![
        (Uuid::new_v4(), "root", false, "OBJECT", false),
        (Uuid::new_v4(), "root/KeyDisclosed", false, "STRING", false),
        (Uuid::new_v4(), "root/KeyHidden", false, "STRING", false),
        (Uuid::new_v4(), "root/nested", false, "OBJECT", false),
        (
            Uuid::new_v4(),
            "root/nested/NestedKeyDisclosed",
            false,
            "STRING",
            false,
        ),
        (
            Uuid::new_v4(),
            "root/nested/NestedKeyAlsoDisclosed",
            false,
            "STRING",
            false,
        ),
        (Uuid::new_v4(), "root2", false, "OBJECT", false),
        (
            Uuid::new_v4(),
            "root2/KeyDisclosed2",
            false,
            "STRING",
            false,
        ),
    ];

    let schema_id = Uuid::new_v4();
    let doctype = "org.iso.23220.1.mID";
    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &server_organisation,
            "NONE",
            &new_claim_schemas,
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
            CreateProofInputSchema::from((
                vec![
                    new_claim_schemas[1],
                    new_claim_schemas[2],
                    new_claim_schemas[3],
                    new_claim_schemas[7],
                ]
                .as_slice(),
                &credential_schema,
            )),
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['KeyDisclosed']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": [format!("$['root']['KeyHidden']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[3].0,
                            "path": [format!("$['root']['nested']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[7].0,
                            "path": [format!("$['root2']['KeyDisclosed2']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
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
        .issuer_create_credential_mdoc(credential_schema.id, doctype, &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

    // // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids_for_mdoc(
        &holder_context,
        &holder_organisation,
        holder_key,
        server_key,
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
            "NONE",
            &new_claim_schemas,
            "MDOC",
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
                    "crv": key_data.crv,
                    "kid": server_local_key.id.to_string(),
                    "kty": key_data.kty,
                    "x": key_data.x,
                    "y": key_data.y,
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['KeyDisclosed']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[3].0,
                            "path": [format!("$['root']['nested']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[7].0,
                            "path": [format!("$['root2']['KeyDisclosed2']")],
                            "optional": true,
                            "intent_to_retain": true
                        },
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
            holder_credential.id,
            vec![
                new_claim_schemas[1].0,
                new_claim_schemas[3].0,
                new_claim_schemas[7].0,
            ],
        )
        .await;

    // // THEN
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let server_proof = server_context.db.proofs.get(&proof.id).await;
    let claims = server_proof.claims.unwrap();
    // Proof sent to the server
    verify_nested_claims(claims);
}

fn verify_nested_claims(claims: Vec<ProofClaim>) {
    assert_eq!(claims.first().unwrap().claim.value, "test");
    assert_eq!(
        claims.first().unwrap().claim.schema.as_ref().unwrap().key,
        "root/KeyDisclosed"
    );
    assert_eq!(claims.get(1).unwrap().claim.value, "test");
    assert_eq!(
        claims.get(1).unwrap().claim.schema.as_ref().unwrap().key,
        "root/nested/NestedKeyAlsoDisclosed"
    );
    assert_eq!(
        claims.get(2).unwrap().claim.schema.as_ref().unwrap().key,
        "root/nested/NestedKeyDisclosed"
    );

    assert_eq!(
        claims.get(3).unwrap().claim.schema.as_ref().unwrap().key,
        "root2/KeyDisclosed2"
    );
}

async fn test_openid4vc_mdoc_flow_array(
    server_key: TestKey,
    holder_key: TestKey,
    issuer_key_type: KeyType,
) {
    // GIVEN
    let interaction_id = Uuid::new_v4();
    let server_context = TestContext::new_with_token(&format!("{}.test", interaction_id)).await;
    let base_url = server_context.config.app.core_base_url.clone();
    let server_organisation = server_context.db.organisations.create().await;
    let nonce = "nonce123";

    let (server_did, holder_did, server_local_key) = prepare_dids_for_mdoc(
        &server_context,
        &server_organisation,
        server_key.to_owned(),
        holder_key.to_owned(),
    )
    .await;

    let key_data = get_key_data(issuer_key_type, server_local_key.clone());

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
    let doctype = "org.iso.23220.1.mID";
    let credential_schema = server_context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "Test",
            &server_organisation,
            "NONE",
            &new_claim_schemas,
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
            CreateProofInputSchema::from((&new_claim_schemas[1..=2], &credential_schema)),
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['array']")],
                            "optional": false,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": [format!("$['root']['object_array']")],
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
        .issuer_create_credential_mdoc(credential_schema.id, doctype, &jwt)
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    // Valid credentials
    let credential_token = resp["credential"].as_str().unwrap();

    // Valid holder context
    let holder_context = TestContext::new().await;
    let holder_organisation = holder_context.db.organisations.create().await;

    let (holder_did, server_did, local_key) = prepare_dids_for_mdoc(
        &holder_context,
        &holder_organisation,
        holder_key,
        server_key,
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
            "NONE",
            &new_claim_schemas,
            "MDOC",
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
            "jwks": [
                {
                    "crv": key_data.crv,
                    "kid": server_local_key.id.to_string(),
                    "kty": key_data.kty,
                    "x": key_data.x,
                    "y": key_data.y,
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
                    "mso_mdoc": {
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
                            "path": [format!("$['root']['array']")],
                            "optional": false,
                            "intent_to_retain": true
                        },
                        {
                            "id": new_claim_schemas[2].0,
                            "path": [format!("$['root']['object_array']")],
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
            holder_credential.id,
            vec![new_claim_schemas[1].0, new_claim_schemas[2].0],
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
