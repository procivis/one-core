use futures::future::join_all;
use one_core::model::blob::BlobType;
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::identifier::Identifier;
use one_core::model::interaction::InteractionType;
use one_core::model::key::Key;
use one_core::model::organisation::{
    Organisation, OrganisationConfiguration, UpdateOrganisationRequest,
};
use one_core::model::proof::{Proof, ProofRole, ProofStateEnum};
use one_core::model::remote_entity_cache::{CacheType, RemoteEntityCacheEntry};
use one_core::provider::key_algorithm::KeyAlgorithm;
use one_core::provider::key_algorithm::ecdsa::Ecdsa;
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::presentation::{
    dummy_presentations, dummy_single_credential_presentations, w3c_jwt_enveloped_presentation,
    w3c_jwt_vc,
};
use crate::fixtures::{
    self, create_credential_schema_with_claims, create_proof, create_proof_schema, get_blob,
    get_proof,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

const NONCE: &str = "nonce123";
const RESPONSE_PATH: &str = "/ssi/openid4vp/final-1.0/response";
type TestClaim<'a> = (Uuid, &'a str, bool, &'a str, bool);

fn string_claim(key: &str, required: bool) -> TestClaim<'_> {
    (Uuid::new_v4(), key, required, "STRING", false)
}

struct DirectPostTest {
    context: TestContext,
    organisation: Organisation,
    verifier_identifier: Identifier,
    verifier_key: Key,
}

impl DirectPostTest {
    async fn new() -> Self {
        let (context, organisation, _, verifier_identifier, verifier_key) =
            TestContext::new_with_did(None).await;
        Self {
            context,
            organisation,
            verifier_identifier,
            verifier_key,
        }
    }

    async fn jwt_schema(&self, name: &str, claims: &[TestClaim<'_>]) -> CredentialSchema {
        create_credential_schema_with_claims(
            &self.context.db.db_conn,
            name,
            &self.organisation,
            false,
            claims,
        )
        .await
    }

    async fn pending_proof(
        &self,
        inputs: &[CreateProofInputSchema<'_>],
        dcql_query: Value,
        profile: Option<&str>,
    ) -> Proof {
        let schema = create_proof_schema(
            &self.context.db.db_conn,
            "Direct post proof",
            &self.organisation,
            inputs,
        )
        .await;
        let interaction = fixtures::create_interaction(
            &self.context.db.db_conn,
            &serde_json::to_vec(&json!({
                "nonce": NONCE,
                "dcql_query": dcql_query,
                "client_id": "client_id",
                "client_id_scheme": "redirect_uri",
                "response_uri": "response_uri"
            }))
            .unwrap(),
            &self.organisation,
            InteractionType::Verification,
        )
        .await;
        create_proof(
            &self.context.db.db_conn,
            &self.verifier_identifier,
            Some(&schema),
            ProofStateEnum::Pending,
            ProofRole::Verifier,
            "OPENID4VP_FINAL1",
            Some(&interaction),
            Some(&self.verifier_key),
            profile.map(str::to_owned),
            None,
        )
        .await
    }

    async fn submit(&self, proof: &Proof, vp_token: &Value) -> reqwest::Response {
        utils::client()
            .post(format!(
                "{}{RESPONSE_PATH}",
                self.context.config.app.core_base_url
            ))
            .form(&[
                ("vp_token", vp_token.to_string()),
                (
                    "state",
                    proof.interaction.as_ref().unwrap().id().to_string(),
                ),
            ])
            .send()
            .await
            .unwrap()
    }

    async fn assert_accepted(&self, proof: &Proof, expected_values: &[&str]) -> Proof {
        let proof = get_proof(&self.context.db.db_conn, &proof.id).await;
        assert_eq!(proof.state, ProofStateEnum::Accepted);
        let claims = proof.claims.as_ref().await.unwrap();
        let mut values: Vec<_> = claims
            .iter()
            .map(|claim| claim.claim.value.as_deref().unwrap())
            .collect();
        values.sort_unstable();
        let mut expected = expected_values.to_vec();
        expected.sort_unstable();
        assert_eq!(values, expected);
        let blob = get_blob(&self.context.db.db_conn, &proof.proof_blob_id.unwrap()).await;
        assert!(str::from_utf8(&blob.value).unwrap().contains("vp_token"));
        assert_eq!(blob.r#type, BlobType::Proof);
        drop(claims);
        proof
    }

    async fn assert_rejected(&self, proof: &Proof) {
        let proof = get_proof(&self.context.db.db_conn, &proof.id).await;
        assert_eq!(proof.state, ProofStateEnum::Error);
        assert!(proof.claims.as_ref().await.unwrap().is_empty());
        assert!(proof.proof_blob_id.is_some());
    }
}

async fn jwt_query(schema: &CredentialSchema, claims: &[TestClaim<'_>]) -> Value {
    json!({
        "id": schema.formats.as_ref().await.unwrap()[0].id,
        "format": "jwt_vc_json",
        "meta": {"type_values": [[
            "https://www.w3.org/2018/credentials#VerifiableCredential",
            format!("{}#{}", schema.schema_id().await.unwrap(), schema.name)
        ]]},
        "claims": claims.iter().map(|(id, key, required, _, _)| json!({
            "id": id, "path": ["credentialSubject", key], "required": required
        })).collect::<Vec<_>>()
    })
}

#[rstest::rstest]
#[case::optional_claim_omitted(false, false, true)]
#[case::required_only_claim_set_satisfied(false, true, true)]
#[case::required_claim_omitted(true, false, false)]
#[tokio::test]
async fn test_direct_post_one_credential(
    #[case] second_claim_required: bool,
    #[case] use_claim_sets: bool,
    #[case] accepted: bool,
) {
    let test = DirectPostTest::new().await;
    let claims = [
        string_claim("cat1", true),
        string_claim("cat2", second_claim_required),
    ];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let mut query = jwt_query(&schema, &claims).await;
    if use_claim_sets {
        query["claim_sets"] = json!([[claims[0].0, claims[1].0], [claims[0].0]]);
    }
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            None,
        )
        .await;
    let (_, token) = dummy_presentations().await;

    let response = test
        .submit(&proof, &json!({query["id"].as_str().unwrap(): [token]}))
        .await;

    assert_eq!(response.status(), if accepted { 200 } else { 400 });
    if accepted {
        let proof = test.assert_accepted(&proof, &["CAT1"]).await;
        let claims = proof.claims.as_ref().await.unwrap();
        assert!(
            claims[0]
                .credential
                .as_ref()
                .await
                .unwrap()
                .issuance_date
                .is_some()
        );
    } else {
        test.assert_rejected(&proof).await;
    }
}

#[tokio::test]
async fn test_direct_post_multiple_credentials_for_one_query() {
    let test = DirectPostTest::new().await;
    let claims = [string_claim("cat1", true), string_claim("cat2", false)];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let mut query = jwt_query(&schema, &claims).await;
    query["multiple"] = json!(true);
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            None,
        )
        .await;
    let (_, token) = dummy_presentations().await;

    let response = test
        .submit(
            &proof,
            &json!({query["id"].as_str().unwrap(): [token, token]}),
        )
        .await;

    assert_eq!(response.status(), 200);
    let proof = test.assert_accepted(&proof, &["CAT1", "CAT1"]).await;
    let claims = proof.claims.as_ref().await.unwrap();
    assert_ne!(claims[0].credential.id(), claims[1].credential.id());
}

#[tokio::test]
async fn test_direct_post_parallel_submissions_only_one_succeeds() {
    let test = DirectPostTest::new().await;
    let claims = [string_claim("cat1", true), string_claim("cat2", false)];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let query = jwt_query(&schema, &claims).await;
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            None,
        )
        .await;
    let (_, token) = dummy_presentations().await;
    let vp_token = json!({query["id"].as_str().unwrap(): [token]});

    let responses = join_all((0..10).map(|_| test.submit(&proof, &vp_token))).await;

    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status() == 200)
            .count(),
        1
    );
    assert_eq!(
        responses
            .iter()
            .filter(|response| response.status() == 400)
            .count(),
        9
    );
    test.assert_accepted(&proof, &["CAT1"]).await;
}

#[tokio::test]
async fn test_direct_post_replay_preserves_accepted_proof() {
    let test = DirectPostTest::new().await;
    let claims = [string_claim("cat1", true)];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let query = jwt_query(&schema, &claims).await;
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            None,
        )
        .await;
    let (_, token) = dummy_presentations().await;
    let vp_token = json!({query["id"].as_str().unwrap(): [token]});
    assert_eq!(test.submit(&proof, &vp_token).await.status(), 200);
    let accepted = test.assert_accepted(&proof, &["CAT1"]).await;

    assert_eq!(test.submit(&proof, &vp_token).await.status(), 400);

    let unchanged = test.assert_accepted(&proof, &["CAT1"]).await;
    assert_eq!(unchanged.proof_blob_id, accepted.proof_blob_id);
    assert_eq!(unchanged.completed_date, accepted.completed_date);
    assert_eq!(unchanged.last_modified, accepted.last_modified);
}

#[rstest::rstest]
#[case::all_inputs_submitted(true)]
#[case::required_inputs_missing(false)]
#[tokio::test]
async fn test_direct_post_multiple_inputs(#[case] submit_all_inputs: bool) {
    let test = DirectPostTest::new().await;
    let name_claims = [string_claim("name1", true), string_claim("name2", false)];
    let pet_claims = [string_claim("pet1", true), string_claim("pet2", false)];
    let cat_claims = [string_claim("cat1", true), string_claim("cat2", false)];
    let name_schema = test.jwt_schema("NameSchema", &name_claims).await;
    let pet_schema = test.jwt_schema("PetSchema", &pet_claims).await;
    let cat_schema = test.jwt_schema("CatSchema", &cat_claims).await;
    // The name and pet presentations also contain claims that were not requested.
    let name_query = jwt_query(&name_schema, &name_claims[..1]).await;
    let pet_query = jwt_query(&pet_schema, &pet_claims[..1]).await;
    let cat_query = jwt_query(&cat_schema, &cat_claims).await;
    let proof = test
        .pending_proof(
            &[
                CreateProofInputSchema::from((&name_claims[..1], &name_schema)),
                CreateProofInputSchema::from((&pet_claims[..1], &pet_schema)),
                CreateProofInputSchema::from((&cat_claims[..], &cat_schema)),
            ],
            json!({"credentials": [name_query, pet_query, cat_query]}),
            None,
        )
        .await;
    let (name_token, pet_token, cat_token) = dummy_single_credential_presentations().await;
    let mut vp_token = json!({cat_query["id"].as_str().unwrap(): [cat_token]});
    if submit_all_inputs {
        vp_token[name_query["id"].as_str().unwrap()] = json!([name_token]);
        vp_token[pet_query["id"].as_str().unwrap()] = json!([pet_token]);
    }

    let response = test.submit(&proof, &vp_token).await;

    assert_eq!(response.status(), if submit_all_inputs { 200 } else { 400 });
    if submit_all_inputs {
        test.assert_accepted(&proof, &["NAME1", "PET1", "CAT1"])
            .await;
    } else {
        test.assert_rejected(&proof).await;
    }
}

#[tokio::test]
async fn test_direct_post_with_profile_verification() {
    let test = DirectPostTest::new().await;
    let profile = "test-verification-profile";
    let claims = [string_claim("cat1", true), string_claim("cat2", false)];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let query = jwt_query(&schema, &claims).await;
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            Some(profile),
        )
        .await;
    let (_, token) = dummy_presentations().await;

    let response = test
        .submit(&proof, &json!({query["id"].as_str().unwrap(): [token]}))
        .await;

    assert_eq!(response.status(), 200);
    let proof = test.assert_accepted(&proof, &["CAT1"]).await;
    assert_eq!(proof.profile.as_deref(), Some(profile));
    for claim in &proof.claims.as_ref().await.unwrap() {
        assert_eq!(
            claim.credential.as_ref().await.unwrap().profile.as_deref(),
            Some(profile)
        );
    }
}

#[tokio::test]
async fn test_direct_post_issuer_untrusted_by_enforced_ecosystem() {
    let test = DirectPostTest::new().await;
    test.context
        .db
        .organisations
        .update(
            &test.organisation.id,
            UpdateOrganisationRequest {
                configuration: Some(OrganisationConfiguration {
                    selected_ecosystems: vec!["EUDI".into()],
                    enforce_ecosystem_as_verifier: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;
    let claims = [string_claim("cat1", true), string_claim("cat2", false)];
    let schema = test.jwt_schema("CatSchema", &claims).await;
    let query = jwt_query(&schema, &claims[..1]).await;
    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((&claims[..], &schema))],
            json!({"credentials": [query]}),
            None,
        )
        .await;
    let (_, token) = dummy_presentations().await;

    let response = test
        .submit(&proof, &json!({query["id"].as_str().unwrap(): [token]}))
        .await;

    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], "Credential issuer untrusted");
    test.assert_rejected(&proof).await;
}

#[tokio::test]
async fn test_direct_post_sd_jwt_vc_no_holder_binding() {
    let test = DirectPostTest::new().await;

    let claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_id, "Full name", true, "STRING", false)];

    let schema_uuid = Uuid::new_v4();
    let credential_schema = test
        .context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_uuid,
            "SdJwtVcSchema",
            &test.organisation,
            &new_claim_schemas,
            "SD_JWT_VC",
            &schema_uuid.to_string(),
        )
        .await;

    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.formats.as_ref().await.unwrap()[0].id.to_string(),
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

    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((
                &new_claim_schemas[..],
                &credential_schema,
            ))],
            dcql_query,
            None,
        )
        .await;

    // Bare SD-JWT-VC token with selective disclosure (no VP wrapper).
    // Contains claim "Full name" = "Eusebio", issued by did:jwk with EdDSA.
    // Captured from a real issuance + presentation flow. No expiration date.
    let bare_sd_jwt_vc = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDpqd2s6ZXlKcmRIa2lPaUpQUzFBaUxDSmpjbllpT2lKRlpESTFOVEU1SWl3aWVDSTZJbk5QV0UxelpsSmhSVmxGYVhSRGJFcEhkV1JQU0hoMVlqZGxUWE42YUZCa1ZsbHBOR290UzFvd01tTWlmUSMwIiwidHlwIjoiZGMrc2Qtand0In0.eyJpYXQiOjE3NzA4MTYyMTgsIm5iZiI6MTc3MDgxNjIxOCwiaXNzIjoiZGlkOmp3azpleUpyZEhraU9pSlBTMUFpTENKamNuWWlPaUpGWkRJMU5URTVJaXdpZUNJNkluTlBXRTF6WmxKaFJWbEZhWFJEYkVwSGRXUlBTSGgxWWpkbFRYTjZhRkJrVmxscE5Hb3RTMW93TW1NaWZRIiwic3ViIjoiZGlkOmtleTp6Nk1ra3N4Y0xKTXAyZFBQTHNERHJzMkE3S1NUbkFSNGo1bXNyNVh5QVFxc3VXYkQiLCJjbmYiOnsiandrIjp7Imt0eSI6Ik9LUCIsImNydiI6IkVkMjU1MTkiLCJ4IjoiWDNudGEtYjEwakQtRUlfM1pNN3A5N19fUGVDVmFMVGJya2w5ZVJaMy1sUSJ9fSwidmN0IjoiaHR0cDovL2xvY2FsaG9zdDozMDAwL3NzaS92Y3QvdjEvMzMzMzMzMzMtMzMzMy0zMzMzLTMzMzMtMzMzMzMzMzMzMzMzLzA2MjgxMTBiLTQ0NGQtNGFhMi05YjIxLTQ5YTlmNjE1NzVjYSIsInZjdCNpbnRlZ3JpdHkiOiJzaGEyNTYtOWtuTjY5VGxRUS83NHJyeE8zZTVJRGZGQnVacW16RUxsZ3ZucU9QejRabz0iLCJfc2QiOlsiZi1IUExybXpYSGJKUWxsYmh1c0RVcjhzY1VoTy1relJNRzJKSFdTdXpGdyJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.K2-juIgi2H2J_Rr9b6z2Q2eR3Sjp8qpDYtgKlyuTDuevZSBnPQb4HRtGpPVQP6yfrmOF_lz2XdeC422OYN0lDQ~WyJOTlhNTmtiWmZvTlBCRXNXa2hob1VRIiwiRnVsbCBuYW1lIiwiRXVzZWJpbyJd~";

    let vp_token = json!({
        credential_schema.formats.as_ref().await.unwrap()[0].id.to_string(): [bare_sd_jwt_vc]
    });

    let response = test.submit(&proof, &vp_token).await;

    assert_eq!(response.status(), 200);
    test.assert_accepted(&proof, &["Eusebio"]).await;
}

#[tokio::test]
async fn test_direct_post_json_ld_classic_no_holder_binding() {
    let test = DirectPostTest::new().await;

    let claim_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_id, "Full name", true, "STRING", false)];

    let schema_uuid = Uuid::new_v4();
    let credential_schema = test
        .context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_uuid,
            "JsonLdSchema",
            &test.organisation,
            &new_claim_schemas,
            "JSON_LD_CLASSIC",
            &schema_uuid.to_string(),
        )
        .await;

    // Pre-populate the JSON-LD context cache with the custom context document
    let context_url = "http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33";
    let context_document = r#"{"@context":{"@version":1.1,"@protected":true,"id":"@id","type":"@type","SchemaJsonLdClassicNoneBasic3Ad6Ca79":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#SchemaJsonLdClassicNoneBasic3Ad6Ca79"},"ProcivisOneSchema2024":{"@context":{"@protected":true,"id":"@id","type":"@type","metadata":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#metadata","@type":"@json"}},"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#ProcivisOneSchema2024"},"Full name":{"@id":"http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33#Full%20name"}}}"#;
    let now = one_core::clock::now_utc();
    test.context
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

    let dcql_query = json!({
        "credentials": [{
            "id": credential_schema.formats.as_ref().await.unwrap()[0].id.to_string(),
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

    let proof = test
        .pending_proof(
            &[CreateProofInputSchema::from((
                &new_claim_schemas[..],
                &credential_schema,
            ))],
            dcql_query,
            None,
        )
        .await;

    // Bare JSON-LD Classic credential with DataIntegrityProof (no VP wrapper).
    // Contains claim "Full name" = "Jedidiah", issued by did:jwk with eddsa-rdfc-2022.
    // Captured from a real issuance + presentation flow. No expiration date.
    let bare_json_ld = r#"{"@context":["https://www.w3.org/ns/credentials/v2","http://localhost:3000/ssi/context/v1/7aec760d-81ee-4027-9192-6ba407ac7e33"],"type":["VerifiableCredential","SchemaJsonLdClassicNoneBasic3Ad6Ca79"],"issuer":"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InI2UEFETzQxRXB6dnFSRWhHMS1laW40YnhvRVp0MlhiSzlLeHMzVUp2NTQifQ","validFrom":"2026-02-11T13:39:58.131228Z","credentialSubject":{"id":"did:key:z6Mkn5hDMfMGoXSwj7MNqqzebShAaZmKzXoHfQ2YdR22aLQ5","Full name":"Jedidiah"},"proof":{"type":"DataIntegrityProof","created":"2026-02-11T13:39:58.131237Z","cryptosuite":"eddsa-rdfc-2022","verificationMethod":"did:jwk:eyJrdHkiOiJPS1AiLCJjcnYiOiJFZDI1NTE5IiwieCI6InI2UEFETzQxRXB6dnFSRWhHMS1laW40YnhvRVp0MlhiSzlLeHMzVUp2NTQifQ#0","proofPurpose":"assertionMethod","proofValue":"z3LeK4wMwYan5Se64TmxgMzLjd5xGSzVbGJR7TQNcjbNrVYE4wyoki526GuARctq2HAUde9FVVnvyJTHnstdxCBn1"},"credentialSchema":{"id":"http://localhost:3000/ssi/schema/v1/7aec760d-81ee-4027-9192-6ba407ac7e33","type":"ProcivisOneSchema2024"}}"#;

    let vp_token = json!({
        credential_schema.formats.as_ref().await.unwrap()[0].id.to_string(): [bare_json_ld]
    });

    let response = test.submit(&proof, &vp_token).await;

    assert_eq!(response.status(), 200);
    test.assert_accepted(&proof, &["Jedidiah"]).await;
}

#[rstest::rstest]
#[case::optional_companion_omitted(false, false, true)]
#[case::required_companion_omitted(true, false, false)]
#[case::required_companion_submitted(true, true, true)]
#[tokio::test]
async fn test_direct_post_multiformat_query_with_optional_and_required_inputs(
    #[case] companion_required: bool,
    #[case] submit_companion: bool,
    #[case] accepted: bool,
) {
    let test = DirectPostTest::new().await;
    let mut credential_schema = test
        .context
        .db
        .credential_schemas
        .create(
            "Identity",
            &test.organisation,
            TestingCreateSchemaParams {
                formats: Some(vec![
                    ("SD_JWT_VC".into(), "identity-vct".into()),
                    ("JWT".into(), "identity-jwt".into()),
                ]),
                ..Default::default()
            },
        )
        .await;
    let companion_schema = test
        .context
        .db
        .credential_schemas
        .create("Companion", &test.organisation, Default::default())
        .await;
    let main_claim = credential_schema.claim_schemas.as_ref().await.unwrap()[0].clone();
    let companion_claim = companion_schema.claim_schemas.as_ref().await.unwrap()[0].clone();
    let mut formats = credential_schema.formats.as_ref().await.unwrap().to_vec();
    formats.sort_by_key(|format| format.format == "JWT".into());
    credential_schema.formats = formats.into();
    let main_claims = [(
        Uuid::from(main_claim.id),
        "firstName",
        true,
        "STRING",
        false,
    )];
    let companion_claims = [(
        Uuid::from(companion_claim.id),
        "firstName",
        companion_required,
        "STRING",
        false,
    )];
    let formats = credential_schema.formats.as_ref().await.unwrap();
    let jwt_format = formats
        .iter()
        .find(|format| format.format == "JWT".into())
        .unwrap();
    let sdjwt_format = formats
        .iter()
        .find(|format| format.format == "SD_JWT_VC".into())
        .unwrap();
    let companion_format = companion_schema.formats.as_ref().await.unwrap()[0].id;
    let mut dcql_query = json!({
        "credentials": [
            {
                "id": sdjwt_format.id,
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["identity-vct"]},
                "claims": [{"id": main_claim.id, "path": ["firstName"], "required": true}]
            },
            {
                "id": jwt_format.id,
                "format": "jwt_vc_json",
                "meta": {"type_values": [["Identity"]]},
                "claims": [{"id": main_claim.id, "path": ["vc", "credentialSubject", "firstName"], "required": true}]
            },
            {
                "id": companion_format,
                "format": "jwt_vc_json",
                "meta": {"type_values": [["Companion"]]},
                "claims": [{"id": companion_claim.id, "path": ["vc", "credentialSubject", "firstName"], "required": companion_required}]
            }
        ],
        "credential_sets": [
            {"required": true, "options": [[sdjwt_format.id], [jwt_format.id]]},
            {"required": companion_required, "options": [[companion_format]]}
        ]
    });
    if !companion_required {
        dcql_query["credentials"][2]["claim_sets"] = json!([[companion_claim.id], []]);
    }
    let proof = test
        .pending_proof(
            &[
                CreateProofInputSchema::from((&main_claims[..], &credential_schema)),
                CreateProofInputSchema::from((&companion_claims[..], &companion_schema)),
            ],
            dcql_query,
            None,
        )
        .await;

    let holder = Ecdsa.generate_key().unwrap();
    let holder_did: shared_types::DidValue =
        format!("did:key:{}", holder.key.public_key_as_multibase().unwrap())
            .parse()
            .unwrap();
    let issuer = Ecdsa.generate_key().unwrap();
    let issuer_did = format!("did:key:{}", issuer.key.public_key_as_multibase().unwrap())
        .parse()
        .unwrap();
    let credential = w3c_jwt_vc(
        &issuer,
        "ES256",
        issuer_did,
        holder_did.clone(),
        json!({"firstName": "Alice"}),
    )
    .await;
    let presentation = w3c_jwt_enveloped_presentation(
        &holder,
        "ES256",
        vec![credential],
        holder_did.clone(),
        holder_did,
        Some(NONCE.to_string()),
    )
    .await;
    let mut vp_token = json!({jwt_format.id.to_string(): [presentation.clone()]});
    if submit_companion {
        vp_token[companion_format.to_string()] = json!([presentation]);
    }
    let response = test.submit(&proof, &vp_token).await;

    assert_eq!(response.status(), if accepted { 200 } else { 400 });
    if !accepted {
        test.assert_rejected(&proof).await;
    } else {
        let expected = if submit_companion {
            vec!["Alice", "Alice"]
        } else {
            vec!["Alice"]
        };
        let proof = test.assert_accepted(&proof, &expected).await;
        let claims = proof.claims.as_ref().await.unwrap();
        assert_eq!(claims.len(), if submit_companion { 2 } else { 1 });
        let main_claim = claims
            .iter()
            .find(|claim| claim.claim.schema.id() == main_claim.id)
            .unwrap();
        assert_eq!(main_claim.claim.value.as_deref(), Some("Alice"));
        let stored = main_claim.credential.as_ref().await.unwrap();
        assert_eq!(stored.format.as_ref().unwrap().id(), jwt_format.id);
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

    let response = utils::client()
        .post(format!(
            "{}{RESPONSE_PATH}",
            context.config.app.core_base_url
        ))
        .form(&[("vp_token", "x".repeat(2048))])
        .send()
        .await
        .unwrap();

    assert_eq!(response.status(), 413);
}
