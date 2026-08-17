use std::collections::BTreeSet;

use futures::future::join_all;
use one_core::model::blob::BlobType;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::interaction::InteractionType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::presentation::{dummy_presentations, dummy_single_credential_presentations};
use crate::fixtures::{
    self, TestingDidParams, TestingIdentifierParams, create_credential_schema_with_claims,
    create_proof, create_proof_schema, get_blob, get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};
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
        false,
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
                "claims": [
                    {
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
                "id": credential_schema.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id().await.unwrap(): [token2]
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

    let claims = proof.claims.as_ref().await.unwrap();
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
        false,
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
                "id": credential_schema.schema_id().await.unwrap(),
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id().await.unwrap(): [token2, token2]
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

    let claims = proof.claims.as_ref().await.unwrap();

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
async fn test_direct_post_dcql_parallel_success() {
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
        false,
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
                "id": credential_schema.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id().await.unwrap(): [token2]
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
    let num_requests = 10;
    let mut multiple_attempts = vec![];
    for _ in 0..num_requests {
        multiple_attempts.push(utils::client().post(url.clone()).form(&params).send());
    }
    // THEN
    let results = join_all(multiple_attempts).await;
    // one attempt must succeed
    let num_successful = results
        .iter()
        .filter(|resp| resp.as_ref().unwrap().status() == 200)
        .count();
    assert_eq!(num_successful, 1);
    // other attempts must fail
    let num_failed = results
        .iter()
        .filter(|resp| resp.as_ref().unwrap().status() == 400)
        .count();
    assert_eq!(num_failed, num_requests - 1);
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
        false,
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
        "dcql_query": {
            "credentials": [{
                "claims": [
                    {
                        "id": new_claim_schemas[0].0,
                        "path": ["credentialSubject", "cat1"],
                        "required": true
                    },
                    {
                        "id": new_claim_schemas[1].0,
                        "path": ["credentialSubject", "cat2"],
                        "required": true
                    }
                ],
                "id": credential_schema.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id().await.unwrap(): [token2]
    });
    let params = [
        ("vp_token", vp_token.to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/final-1.0/response");

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
    let claims = proof.claims.as_ref().await.unwrap();
    assert!(claims.is_empty());
}

#[tokio::test]
async fn test_direct_post_multiple_presentations() {
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
        false,
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &context.db.db_conn,
        "PetSchema",
        &organisation,
        false,
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &context.db.db_conn,
        "CatSchema",
        &organisation,
        false,
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
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
        "dcql_query": {
            "credentials": [
            {
                "claims": [{
                    "id": credential1_claims[0].0,
                    "path": ["credentialSubject", "name1"],
                    "required": true
                }],
                "id": credential_schema1.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
                }
            },
            {
                "claims": [{
                    "id": credential2_claims[0].0,
                    "path": ["credentialSubject", "pet1"],
                    "required": true
                }],
                "id": credential_schema2.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
                }
            },
            {
                "claims": [
                    {
                        "id": credential3_claims[0].0,
                        "path": ["credentialSubject", "cat1"],
                        "required": true
                    },
                    {
                        "id": credential3_claims[1].0,
                        "path": ["credentialSubject", "cat2"],
                        "required": false
                    }
                ],
                "id": credential_schema3.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    let (name_presentation, pet_presentation, cat_presentation) =
        dummy_single_credential_presentations().await;
    let vp_token = json!({
        credential_schema1.schema_id().await.unwrap(): [name_presentation],
        credential_schema2.schema_id().await.unwrap(): [pet_presentation],
        credential_schema3.schema_id().await.unwrap(): [cat_presentation],
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

    let expected_claims: BTreeSet<String> = proof_input_schemas
        .into_iter()
        .flat_map(|c| c.claims)
        .filter_map(|c| c.required.then_some(c.key.to_ascii_uppercase()))
        .collect();

    let claims: BTreeSet<String> = proof
        .claims
        .as_ref()
        .await
        .unwrap()
        .into_iter()
        .map(|c| c.claim.value.clone().unwrap())
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
        false,
        &credential1_claims,
    )
    .await;

    let credential_schema2 = create_credential_schema_with_claims(
        &db_conn,
        "PetSchema",
        &organisation,
        false,
        &credential2_claims,
    )
    .await;

    let credential_schema3 = create_credential_schema_with_claims(
        &db_conn,
        "CatSchema",
        &organisation,
        false,
        &credential3_claims,
    )
    .await;

    let proof_input_schemas = [
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential1_claims[0]), // name1
            ],
            credential_schema: &credential_schema1,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential2_claims[0]), // pet1
            ],
            credential_schema: &credential_schema2,
        },
        CreateProofInputSchema {
            claims: vec![
                CreateProofClaim::from(&credential3_claims[0]), // cat1
                CreateProofClaim::from(&credential3_claims[1]), // cat2 (optional)
            ],
            credential_schema: &credential_schema3,
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
        "dcql_query": {
            "credentials": [
            {
                "claims": [{
                    "id": credential1_claims[0].0,
                    "path": ["credentialSubject", "name1"],
                    "required": true
                }],
                "id": credential_schema1.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
                }
            },
            {
                "claims": [{
                    "id": credential2_claims[0].0,
                    "path": ["credentialSubject", "pet1"],
                    "required": true
                }],
                "id": credential_schema2.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
                }
            },
            {
                "claims": [
                    {
                        "id": credential3_claims[0].0,
                        "path": ["credentialSubject", "cat1"],
                        "required": true
                    },
                    {
                        "id": credential3_claims[1].0,
                        "path": ["credentialSubject", "cat2"],
                        "required": false
                    }
                ],
                "id": credential_schema3.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        None,
        None,
    )
    .await;

    // only the cat credential is presented; the required name and pet credentials are missing
    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema3.schema_id().await.unwrap(): [token2]
    });
    let params = [
        ("vp_token", vp_token.to_string()),
        ("state", interaction.id.to_string()),
    ];

    // WHEN
    let _handle = run_server(listener, config, &db_conn).await;

    let url = format!("{base_url}/ssi/openid4vp/final-1.0/response");

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
        false,
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
                "claims": [
                    {
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
                "id": credential_schema.schema_id().await.unwrap(),
                "format": "jwt_vc_json",
                "meta": {
                    "type_values": [["https://www.w3.org/2018/credentials#VerifiableCredential"]],
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
        "OPENID4VP_FINAL1",
        Some(&interaction),
        Some(&verifier_key),
        Some(test_profile.to_string()),
        None,
    )
    .await;

    let (_, token2) = dummy_presentations().await;
    let vp_token = json!({
        credential_schema.schema_id().await.unwrap(): [token2]
    });
    let params = [
        ("vp_token", vp_token.to_string()),
        (
            "state",
            proof.interaction.as_ref().unwrap().id().to_string(),
        ),
    ];

    // WHEN
    let url = format!("{base_url}/ssi/openid4vp/final-1.0/response");
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

    let claims = proof.claims.as_ref().await.unwrap();
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
    for claim in &claims {
        assert_eq!(
            claim.credential.as_ref().await.unwrap().profile,
            Some(test_profile.to_string())
        );
    }
}

#[tokio::test]
async fn test_direct_post_oversized_body_returns_413() {
    let context = TestContext::new(Some(
        indoc::indoc! {"
            app:
                maxLargeExternalRequestBodyBytes: 1024
        "}
        .to_string(),
    ))
    .await;

    let oversized_token = "x".repeat(2048);
    let params = [("vp_token", oversized_token)];

    for path in ["/ssi/openid4vp/final-1.0/response"] {
        let url = format!("{}{path}", context.config.app.core_base_url);
        let resp = utils::client()
            .post(url)
            .form(&params)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            413,
            "expected 413 Payload Too Large from {path}",
        );
    }
}
