use std::collections::BTreeSet;

use one_core::model::blob::BlobType;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::interaction::InteractionType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::json;
use shared_types::DidValue;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::presentation::{
    dummy_presentation_with_lvvc, dummy_presentations, w3c_jwt_enveloped_presentation,
    w3c_jwt_vc_with_lvvc,
};
use crate::fixtures::{
    self, TestingDidParams, TestingIdentifierParams, create_credential_schema_with_claims,
    create_proof, create_proof_schema, get_blob, get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
use crate::utils::field_match::FieldHelpers;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_direct_post_one_credential_correct() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
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
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", token2),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!(
        "{}/ssi/openid4vp/draft-20/response",
        context.config.app.core_base_url
    );
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();
    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(
                    |db_claim| db_claim.claim.value == Some(required_claim.1.to_ascii_uppercase())
                ))
    );

    let blob = get_blob(&context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
    assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
    assert_eq!(blob.r#type, BlobType::Proof);
}

#[tokio::test]
async fn test_direct_post_one_credential_lvvc_success() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "LVVC",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
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
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[1]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let vp_token = dummy_presentation_with_lvvc().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", vp_token),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!(
        "{}/ssi/openid4vp/draft-20/response",
        context.config.app.core_base_url
    );
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();
    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(
                    |db_claim| db_claim.claim.value == Some(required_claim.1.to_ascii_uppercase())
                ))
    );

    let blob = get_blob(&context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
    assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
    assert_eq!(blob.r#type, BlobType::Proof);
}

#[tokio::test]
async fn test_direct_post_multiple_credentials_lvvc_repeated_input_descriptors() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let credential1_claims = vec![
        (Uuid::new_v4(), "name1", true, "STRING", false), // Presentation 1 token 1
        (Uuid::new_v4(), "name2", false, "STRING", false), // Provided, not requested
    ];

    let credential2_claims = vec![
        (Uuid::new_v4(), "pet1", true, "STRING", false), // Presentation 1 token 0
        (Uuid::new_v4(), "pet2", false, "STRING", false), // Provided, not requested
    ];

    let credential3_claims = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 0
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided but requested
    ];

    let credential_schema1 = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NameSchema",
        &organisation,
        "NONE",
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &context.db.db_conn,
        "PetSchema",
        &organisation,
        "NONE",
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &context.db.db_conn,
        "CatSchema",
        &organisation,
        "LVVC",
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
            validity_constraint: None,
        },
    ];

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &proof_input_schemas,
    )
    .await;
    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema1.schema_id
                            }
                        },
                        {
                            "id": credential1_claims[0].0,
                            "path": ["$.vc.credentialSubject.name1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema2.schema_id
                            }
                        },
                        {
                            "id": credential2_claims[0].0,
                            "path": ["$.vc.credentialSubject.pet1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_2",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema3.schema_id
                            }
                        },
                        {
                            "id": credential3_claims[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": credential3_claims[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        },
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[1]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_1",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[1]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[1]"
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (vp_token_1, _) = dummy_presentations().await;
    let vp_token_2 = dummy_presentation_with_only_lvvc().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", json!([vp_token_1, vp_token_2]).to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!(
        "{}/ssi/openid4vp/draft-20/response",
        context.config.app.core_base_url
    );
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
    let result = resp.json::<serde_json::Value>().await.unwrap();
    result["error"].assert_eq(&"invalid_request".to_string());
}

pub(crate) async fn dummy_presentation_with_only_lvvc() -> String {
    let alg = "ES256";
    let holder_key_pair = Ecdsa.generate_key().unwrap();
    let multibase = holder_key_pair.key.public_key_as_multibase().unwrap();
    let holder_did = DidValue::from_did_url(format!("did:key:{}", multibase).as_str()).unwrap();

    let issuer_key_pair = Ecdsa.generate_key().unwrap();
    let multibase = issuer_key_pair.key.public_key_as_multibase().unwrap();
    let issuer_did = DidValue::from_did_url(format!("did:key:{}", multibase).as_str()).unwrap();

    let cat_cred_subj = json!({
      "cat1": "CAT1"
    });

    let (_, lvvc) = w3c_jwt_vc_with_lvvc(
        &issuer_key_pair,
        alg,
        issuer_did,
        holder_did.clone(),
        cat_cred_subj,
    )
    .await;

    w3c_jwt_enveloped_presentation(
        &holder_key_pair,
        alg,
        vec![lvvc],
        holder_did.clone(),
        holder_did,
        Some("nonce123".to_string()),
    )
    .await
}

#[tokio::test]
async fn test_direct_post_dcql_multiple_flag_true_success() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": {
            "credentials": [{
                "claims": [{
                    "id": new_claim_schemas[0].0,
                    "path": ["credentialSubject", "cat1"],
                    "required": true
                },
                {
                    "id": new_claim_schemas[1].0,
                    "path": ["credentialSubject", "cat2"],
                    "required": false
                }
                ],
                "id": credential_schema.schema_id,
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
                },
                "multiple": true
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_FINAL1_0",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id: [token2, token2]
    });

    let params = [
        ("vp_token", vp_token.to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!(
        "{}/ssi/openid4vp/final-1.0/response",
        context.config.app.core_base_url
    );
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();

    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(
                    |db_claim| db_claim.claim.value == Some(required_claim.1.to_ascii_uppercase())
                ))
    );

    let blob = get_blob(&context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
    assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
    assert_eq!(blob.r#type, BlobType::Proof);
}

#[tokio::test]
async fn test_direct_post_one_credential_missing_required_claim() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", true, "STRING", false), // required - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let verifier_key = fixtures::create_key(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: verifier_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let verifier_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(verifier_did),
            ..Default::default()
        }),
    )
    .await;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": false
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", token2),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());
}

#[tokio::test]
async fn test_direct_post_multiple_presentations() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let credential1_claims = vec![
        (Uuid::new_v4(), "name1", true, "STRING", false), // Presentation 1 token 1
        (Uuid::new_v4(), "name2", false, "STRING", false), // Provided, not requested
    ];

    let credential2_claims = vec![
        (Uuid::new_v4(), "pet1", true, "STRING", false), // Presentation 1 token 0
        (Uuid::new_v4(), "pet2", false, "STRING", false), // Provided, not requested
    ];

    let credential3_claims = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 0
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided but requested
    ];

    let credential_schema1 = create_credential_schema_with_claims(
        &db_conn,
        "NameSchema",
        &organisation,
        "NONE",
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &db_conn,
        "PetSchema",
        &organisation,
        "NONE",
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &db_conn,
        "CatSchema",
        &organisation,
        "NONE",
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
            validity_constraint: None,
        },
    ];

    let proof_schema =
        create_proof_schema(&db_conn, "Schema1", &organisation, &proof_input_schemas).await;

    let verifier_key = fixtures::create_key(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: verifier_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let verifier_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(verifier_did),
            ..Default::default()
        }),
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema1.schema_id
                            }
                        },
                        {
                            "id": credential1_claims[0].0,
                            "path": ["$.vc.credentialSubject.name1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema2.schema_id
                            }
                        },
                        {
                            "id": credential2_claims[0].0,
                            "path": ["$.vc.credentialSubject.pet1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_2",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema3.schema_id
                            }
                        },
                        {
                            "id": credential3_claims[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": credential3_claims[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        },
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[1]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_1",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[1]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[1].verifiableCredential[0]"
                    }
            }
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (token1, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", json!([token1, token2]).to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let expected_claims: BTreeSet<String> = proof_input_schemas
        .into_iter()
        .flat_map(|c| c.claims)
        .filter_map(|c| c.required.then_some(c.key.to_ascii_uppercase()))
        .collect();

    let claims: BTreeSet<String> = proof
        .claims
        .unwrap()
        .into_iter()
        .map(|c| c.claim.value.unwrap())
        .collect();

    assert_eq!(expected_claims, claims);

    // TODO: Add additional checks when https://procivis.atlassian.net/browse/ONE-1133 is implemented
}

#[tokio::test]
async fn test_direct_post_multiple_presentations_missing_inputs() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let credential1_claims = vec![
        (Uuid::new_v4(), "name1", true, "STRING", false), // Presentation 1 token 1
        (Uuid::new_v4(), "name2", false, "STRING", false), // Provided, not requested
    ];

    let credential2_claims = vec![
        (Uuid::new_v4(), "pet1", true, "STRING", false), // Presentation 1 token 0
        (Uuid::new_v4(), "pet2", false, "STRING", false), // Provided, not requested
    ];

    let credential3_claims = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 0
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided but requested
    ];

    let credential_schema1 = create_credential_schema_with_claims(
        &db_conn,
        "NameSchema",
        &organisation,
        "NONE",
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &db_conn,
        "PetSchema",
        &organisation,
        "NONE",
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &db_conn,
        "CatSchema",
        &organisation,
        "NONE",
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
            validity_constraint: None,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
            validity_constraint: None,
        },
    ];

    let proof_schema =
        create_proof_schema(&db_conn, "Schema1", &organisation, &proof_input_schemas).await;

    let verifier_key = fixtures::create_key(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: verifier_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let verifier_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(verifier_did),
            ..Default::default()
        }),
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema1.schema_id
                            }
                        },
                        {
                            "id": credential1_claims[0].0,
                            "path": ["$.vc.credentialSubject.name1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_1",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema2.schema_id
                            }
                        },
                        {
                            "id": credential2_claims[0].0,
                            "path": ["$.vc.credentialSubject.pet1"],
                            "optional": false
                        },
                    ]
                }
            },
            {
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
                    }
                },
                "id": "input_2",
                "constraints": {
                    "fields": [
                        {
                            "path": ["$.credentialSchema.id"],
                            "filter": {
                                "type": "string",
                                "const": credential_schema3.schema_id
                            }
                        },
                        {
                            "id": credential3_claims[0].0,
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": credential3_claims[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        },
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            },
            {
                "format": "jwt_vp_json",
                "id": "input_2",
                "path": "$[0]",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$[0].verifiableCredential[0]"
                    }
            }
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", json!([token2]).to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
}

#[tokio::test]
async fn test_direct_post_wrong_claim_format() {
    // GIVEN
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let config = fixtures::create_config(&base_url, None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let verifier_key = fixtures::create_key(&db_conn, &organisation, None).await;
    let verifier_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: verifier_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let verifier_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(verifier_did),
            ..Default::default()
        }),
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "vc+sd-jwt": {
                        "kb-jwt_alg_values": ["EdDSA", "ES256"],
                        "sd-jwt_alg_values": ["EdDSA", "ES256"]
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
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", token2.to_owned()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");

    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    let status_code = resp.status();
    assert_eq!(status_code, 400);

    let proof = get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());
}

#[tokio::test]
async fn test_direct_post_draft25() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
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
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT25",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": interaction.id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", token2),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let url = format!(
        "{}/ssi/openid4vp/draft-25/response",
        context.config.app.core_base_url
    );
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();
    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(
                    |db_claim| db_claim.claim.value == Some(required_claim.1.to_ascii_uppercase())
                ))
    );
}

#[tokio::test]
async fn test_direct_post_with_profile_verification() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";
    let test_profile = "test-verification-profile";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Required claim
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        &[CreateProofInputSchema::from((
            &new_claim_schemas[..],
            &credential_schema,
        ))],
    )
    .await;

    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "format": {
                    "jwt_vc_json": {
                        "alg": ["EdDSA", "ES256"]
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
                            "path": ["$.vc.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.vc.credentialSubject.cat2"],
                            "optional": true
                        }
                    ]
                }
            }]
        },
        "client_id": "client_id",
        "client_id_scheme": "redirect_uri",
        "response_uri": "response_uri"
    });

    let base_url = context.config.app.core_base_url.clone();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        &organisation,
        InteractionType::Verification,
    )
    .await;

    // Create proof with profile - manually since fixture doesn't support profiles
    let proof = create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        Some(&proof_schema),
        ProofStateEnum::Pending,
        ProofRole::Verifier,
        "OPENID4VP_DRAFT25",
        Some(&interaction),
        Some(&verifier_key),
        Some(test_profile.to_string()),
        None,
    )
    .await;

    let presentation_submission = json!({
        "definition_id": proof.interaction.as_ref().unwrap().id,
        "descriptor_map": [
            {
                "format": "jwt_vp_json",
                "id": "input_0",
                "path": "$",
                "path_nested": {
                        "format": "jwt_vc_json",
                        "path": "$.verifiableCredential[0]"
                    }
            },
        ],
        "id": "318ea550-dbb6-4d6a-9cf2-575bad15c6da"
    });

    let (_, token2) = dummy_presentations().await;
    let params = [
        (
            "presentation_submission",
            presentation_submission.to_string(),
        ),
        ("vp_token", token2),
        ("state", proof.interaction.as_ref().unwrap().id.to_string()),
    ];

    // WHEN
    let url = format!("{base_url}/ssi/openid4vp/draft-20/response");
    let resp = utils::client()
        .post(url)
        .form(&params)
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();
    assert!(
        new_claim_schemas
            .iter()
            .filter(|required_claim| required_claim.2) //required
            .all(|required_claim| claims
                .iter()
                // Values are just keys uppercase
                .any(
                    |db_claim| db_claim.claim.value == Some(required_claim.1.to_ascii_uppercase())
                ))
    );

    assert_eq!(proof.profile, Some(test_profile.to_string()));
    assert_eq!(
        claims
            .iter()
            .all(|claim| claim.credential.as_ref().unwrap().profile
                == Some(test_profile.to_string())),
        true
    );
}
