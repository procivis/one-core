use std::str;

use one_core::model::blob::BlobType;
use one_core::model::interaction::InteractionType;
use one_core::model::proof::{ProofRole, ProofStateEnum};
use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::presentation::dummy_presentations;
use crate::fixtures::{
    self, create_credential_schema_with_claims, create_proof, create_proof_schema, get_blob,
    get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

#[tokio::test]
async fn test_direct_post_draft25_with_dcql_query() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Required claim
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional claim - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        None,
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

    // Create DCQL query instead of presentation definition
    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "jwt_vc_json",
            "require_cryptographic_holder_binding": true,
            "meta": {
                "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    format!("{}#{}", credential_schema.schema_id, "NewCredentialSchema")
                ]]
            },
            "claims": [
                {
                    "id": new_claim_schemas[0].0.to_string(),
                    "path": ["credentialSubject", "cat1"],
                    "required": true
                },
                {
                    "id": new_claim_schemas[1].0.to_string(),
                    "path": ["credentialSubject", "cat2"],
                    "required": false
                }
            ],
            "claim_sets": [
                [
                    new_claim_schemas[0].0.to_string(),
                    new_claim_schemas[1].0.to_string()
                ],
                [
                    new_claim_schemas[0].0.to_string()
                ]
            ]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
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

    // For DCQL, vp_token is a HashMap<String, Vec<String>> sent as JSON string
    let (_, token2) = dummy_presentations().await;
    let vp_token_map = json!({
        credential_schema.id.to_string(): [token2]
    });

    let params = [
        ("vp_token", vp_token_map.to_string()),
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
    // Note: This test may fail until DCQL processing is fully implemented
    // (the service method currently has a todo!())
    assert_eq!(resp.status(), 200);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);

    let claims = proof.claims.unwrap();
    assert!(
        claims
            .first()
            .as_ref()
            .unwrap()
            .credential
            .as_ref()
            .unwrap()
            .issuance_date
            .is_some()
    );
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
async fn test_direct_post_dcql_one_credential_missing_required_claim() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false), // Required claim
        (Uuid::new_v4(), "cat2", true, "STRING", false), // Required - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "NewCredentialSchema",
        &organisation,
        None,
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

    // Create DCQL query with both required claims
    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "jwt_vc_json",
            "require_cryptographic_holder_binding": true,
            "meta": {
                "type_values": [[
                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                    format!("{}#{}", credential_schema.schema_id, "NewCredentialSchema")
                ]]
            },
            "claims": [
                {
                    "id": new_claim_schemas[0].0.to_string(),
                    "path": ["credentialSubject", "cat1"],
                    "required": true
                },
                {
                    "id": new_claim_schemas[1].0.to_string(),
                    "path": ["credentialSubject", "cat2"],
                    "required": true
                }
            ]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
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

    let (_, token2) = dummy_presentations().await;
    // Send token that only has cat1 but not cat2 (which is required)
    let vp_token_map = json!({
        credential_schema.id.to_string(): [token2]
    });

    let params = [
        ("vp_token", vp_token_map.to_string()),
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
    assert_eq!(resp.status(), 400);

    let proof = get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Error);
    let claims = proof.claims.unwrap();
    assert!(claims.is_empty());

    assert!(proof.proof_blob_id.is_some());
}

#[tokio::test]
async fn test_direct_post_dcql_sd_jwt_vc_no_holder_binding() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_id, "Full name", true, "STRING", false)];

    let schema_uuid = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_uuid,
            "SdJwtVcSchema",
            &organisation,
            None,
            &new_claim_schemas,
            "SD_JWT_VC",
            &schema_uuid.to_string(),
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

    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "dc+sd-jwt",
            "require_cryptographic_holder_binding": false,
            "meta": {
                "vct_values": [
                    "http://localhost:3000/ssi/vct/v1/33333333-3333-3333-3333-333333333333/0628110b-444d-4aa2-9b21-49a9f61575ca"
                ]
            },
            "claims": [{
                "id": claim_id.to_string(),
                "path": ["Full name"],
                "required": true
            }]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
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

    // Bare SD-JWT-VC token with selective disclosure (no VP wrapper).
    // Contains claim "Full name" = "Eusebio", issued by did:jwk with EdDSA.
    // Captured from a real issuance + presentation flow. No expiration date.
    let bare_sd_jwt_vc = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbk5QV0UxelpsSmhSVmxGYVhSRGJFcEhkV1JQU0hoMVlqZGxUWE42YUZCa1ZsbHBOR290UzFvd01tTWlmUSMwIiwidHlwIjoiZGMrc2Qtand0In0.eyJpYXQiOjE3NzA4MTYyMTgsIm5iZiI6MTc3MDgxNjIxOCwiaXNzIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluTlBXRTF6WmxKaFJWbEZhWFJEYkVwSGRXUlBTSGgxWWpkbFRYTjZhRkJrVmxscE5Hb3RTMW93TW1NaWZRIiwic3ViIjoiZGlkOmtleTp6Nk1ra3N4Y0xKTXAyZFBQTHNERHJzMkE3S1NUbkFSNGo1bXNyNVh5QVFxc3VXYkQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiWDNudGEtYjEwakQtRUlfM1pNN3A5N19fUGVDVmFMVGJya2w5ZVJaMy1sUSJ9fSwidmN0IjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3NzaS92Y3QvdjEvMzMzMzMzMzMtMzMzMy0zMzMzLTMzMzMtMzMzMzMzMzMzMzMzLzA2MjgxMTBiLTQ0NGQtNGFhMi05YjIxLTQ5YTlmNjE1NzVjYSIsInZjdCNpbnRlZ3JpdHkiOiJzaGEyNTYtOWtuTjY5VGxRUS83NHJyeE8zZTVJRGZGQnVacW16RUxsZ3ZucU9QejRabz0iLCJfc2QiOlsiZi1IUExybXpYSGJKUWxsYmh1c0RVcjhzY1VoTy1relJNRzJKSFdTdXpGdyJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.K2-juIgi2H2J_Rr9b6z2Q2eR3Sjp8qpDYtgKlyuTDuevZSBnPQb4HRtGpPVQP6yfrmOF_lz2XdeC422OYN0lDQ~WyJOTlhNTmtiWmZvTlBCRXNXa2hob1VRIiwiRnVsbCBuYW1lIiwiRXVzZWJpbyJd~";

    let vp_token = json!({
        credential_schema.id.to_string(): [bare_sd_jwt_vc]
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
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].claim.value, Some("Eusebio".to_string()));

    let blob = get_blob(&context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
    assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
    assert_eq!(blob.r#type, BlobType::Proof);
}

#[tokio::test]
async fn test_direct_post_dcql_json_ld_classic_no_holder_binding() {
    // GIVEN
    let (context, organisation, _, verifier_identifier, verifier_key) =
        TestContext::new_with_did(None).await;
    let nonce = "nonce123";

    let claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_id, "Full name", true, "STRING", false)];

    let schema_uuid = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_uuid,
            "JsonLdSchema",
            &organisation,
            None,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
            &schema_uuid.to_string(),
        )
        .await;

    // Pre-populate the JSON-LD context cache with the custom context document
    let context_url = "http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33";
    let context_document = r#"{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","SchemaJsonLdClassicNoneBasic3Ad6Ca79":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#SchemaJsonLdClassicNoneBasic3Ad6Ca79"},"ProcivisOneSchema2024":{"@context":{"@protected":true,"id":"@id","type":"@type","metadata":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#metadata","@type":"@json"}},"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#ProcivisOneSchema2024"},"Full name":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#Full%20name"}}}"#;
    let now = one_core::clock::now_utc();
    context
        .db
        .remote_entities
        .add_entry(RemoteEntityCacheEntry {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            last_used: now,
            expiration_date: Some(now + time::Duration::days(30)),
            key: context_url.to_string(),
            value: context_document.as_bytes().to_vec(),
            r#type: CacheType::JsonLdContext,
            media_type: Some("application/ld+json".to_string()),
        })
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

    // DCQL query: ldp_vc format, no holder binding required
    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.id.to_string(),
            "format": "ldp_vc",
            "require_cryptographic_holder_binding": false,
            "meta": {
                "type_values": [
                    ["VerifiableCredential", "SchemaJsonLdClassicNoneBasic3Ad6Ca79"]
                ]
            },
            "claims": [{
                "id": claim_id.to_string(),
                "path": ["credentialSubject", "Full name"],
                "required": true
            }]
        }]
    });

    let interaction_data = json!({
        "nonce": nonce,
        "dcql_query": dcql_query,
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

    // Bare JSON-LD Classic credential with DataIntegrityProof (no VP wrapper).
    // Contains claim "Full name" = "Jedidiah", issued by did:jwk with eddsa-rdfc-2022.
    // Captured from a real issuance + presentation flow. No expiration date.
    let bare_json_ld = r#"{"@context":["https://www.w3.org/ns/credentials/v2","http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33"],"type":["VerifiableCredential","SchemaJsonLdClassicNoneBasic3Ad6Ca79"],"issuer":"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InI2UEFETzQxRXB6dnFSRWhHMS1laW40YnhvRVp0MlhiSzlLeHMzVUp2NTQifQ","validFrom":"2026-02-11T13:39:58.131228Z","credentialSubject":{"id":"did:key:z6Mkn5hDMfMGoXSwj7MNqqzebShAaZmKzXoHfQ2YdR22aLQ5","Full name":"Jedidiah"},"proof":{"type":"DataIntegrityProof","created":"2026-02-11T13:39:58.131237Z","cryptosuite":"eddsa-rdfc-2022","verificationMethod":"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InI2UEFETzQxRXB6dnFSRWhHMS1laW40YnhvRVp0MlhiSzlLeHMzVUp2NTQifQ#0","proofPurpose":"assertionMethod","proofValue":"z3LeK4wMwYan5Se64TmxgMzLjd5xGSzVbGJR7TQNcjbNrVYE4wyoki526GuARctq2HAUde9FVVnvyJTHnstdxCBn1"},"credentialSchema":{"id":"http://localhost:3000/ssi/schema/v1/7aec760d-81ee-4027-9192-6ba407ac7e33","type":"ProcivisOneSchema2024"}}"#;

    let vp_token = json!({
        credential_schema.id.to_string(): [bare_json_ld]
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
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].claim.value, Some("Jedidiah".to_string()));

    let blob = get_blob(&context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
    assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
    assert_eq!(blob.r#type, BlobType::Proof);
}
