use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::Interaction;
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofRole, ProofStateEnum};
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::http::Method;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockBuilder, MockServer, ResponseTemplate};

use crate::fixtures::{
    self, TestingCredentialParams, TestingCredentialSchemaParams, TestingDidParams,
    TestingIdentifierParams, TestingKeyParams, create_credential_schema_with_claims,
};
use crate::utils;
use crate::utils::context::TestContext;
use crate::utils::server::run_server;

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vc() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let client_metadata = json!(
    {
        "jwks": {
            "keys": [{
                "crv": "P-256",
                "kid": "not-a-uuid",
                "kty": "EC",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                "use": "enc"
            }]
        },
        "vp_formats":
        {
            "jwt_vp_json":
            {
                "alg":["EdDSA"]
            },
            "jwt_vc_json":{
                "alg":["EdDSA"]
            },
            "ldp_vp":{
                "proof_type":["DataIntegrityProof"]
            },
            "mso_mdoc":{
                "alg":["EdDSA"]
            },
            "vc+sd-jwt": {
                "kb-jwt_alg_values": ["EdDSA", "ES256"],
                "sd-jwt_alg_values": ["EdDSA", "ES256"]
            }
        }
    });

    let (holder_did, _, verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation(
            &context,
            &organisation,
            &identifier,
            &client_metadata.to_string(),
        )
        .await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f"))
                .and(body_string_contains("vp_token"))
                .and(body_string_contains("descriptor_map"))
                .and(body_string_contains("input_0"))
                .and(body_string_contains("jwt_vp_json")) // As we use jwt as credential input. Temporary.
                .and(body_string_contains("verifiableCredential"))
        }))
        .await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v1/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "didId": holder_did.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": [
                credential.claims.unwrap().first().unwrap().id
              ]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.claim.value == "test")
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
    );
    assert_eq!(
        proof.holder_identifier.unwrap().did.unwrap().did,
        holder_did.did
    );
    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &verifier_identifier.id.to_string()
    )
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vc_encrypted() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let client_metadata = json!({
        "authorization_encrypted_response_alg": "ECDH-ES",
        "authorization_encrypted_response_enc": "A128CBC-HS256",
        "jwks": {
            "keys": [{
                "crv": "P-256",
                "kid": "not-a-uuid",
                "kty": "EC",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                "use": "enc"
            }]
        },
        "vp_formats":
        {
            "jwt_vp_json":
            {
                "alg":["EdDSA"]
            },
            "jwt_vc_json":{
                "alg":["EdDSA"]
            },
            "ldp_vp":{
                "proof_type":["DataIntegrityProof"]
            },
            "mso_mdoc":{
                "alg":["EdDSA"]
            },
            "vc+sd-jwt": {
                "kb-jwt_alg_values": ["EdDSA", "ES256"],
                "sd-jwt_alg_values": ["EdDSA", "ES256"]
            }
        }
    });

    let (holder_did, _, verifier_did, _, credential, interaction, proof) =
        setup_submittable_presentation(
            &context,
            &organisation,
            &identifier,
            &client_metadata.to_string(),
        )
        .await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // expect single response parameter
            mock_builder.and(body_string_contains("response"))
        }))
        .await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v1/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "didId": holder_did.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": [
                credential.claims.unwrap().first().unwrap().id
              ]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.claim.value == "test")
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
    );
    assert_eq!(
        proof.holder_identifier.unwrap().did.unwrap().did,
        holder_did.did
    );
}

async fn setup_submittable_presentation(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
    client_metadata: &str,
) -> (
    Did,
    Identifier,
    Did,
    Identifier,
    Credential,
    Interaction,
    Proof,
) {
    let verifier_key = context
        .db
        .keys
        .create(organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: verifier_key.clone(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let holder_key = fixtures::create_key(
        &context.db.db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
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
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &context.db.db_conn,
        organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".to_string()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key,
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = fixtures::create_credential_schema(
        &context.db.db_conn,
        organisation,
        Some(TestingCredentialSchemaParams {
            name: Some("Schema1".to_string()),
            ..Default::default()
        }),
    )
    .await;

    let credential = fixtures::create_credential(
        &context.db.db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        issuer_identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams {
            holder_identifier: Some(holder_identifier.clone()),
            role: Some(CredentialRole::Holder),
            credential: Some("TOKEN"),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = context.server_mock.uri();
    let claims = credential.claims.clone().unwrap();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        &verifier_url,
        json!(
            {
                "response_type":"vp_token",
                "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
                "nonce":"QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
                "client_id_scheme":"redirect_uri",
                "client_id": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "client_metadata": client_metadata,
                "response_mode":"direct_post",
                "response_uri": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "presentation_definition":
                {
                    "id":"fa42f6f7-f1a7-4af6-aa0e-970468cc4b3f",
                    "input_descriptors":
                    [
                        {
                            "format": {
                                "jwt_vc_json": {
                                    "alg": ["EdDSA", "ES256"]
                                }
                            },
                            "id":"input_0",
                            "constraints":{
                                "fields":[
                                    {
                                        "path":["$.credentialSchema.id"],
                                        "filter": {
                                            "type": "string",
                                            "const": credential_schema.schema_id
                                        }
                                    },
                                    {
                                        "id": claims[0].id,
                                        "path":["$.vc.credentialSubject.firstName"],
                                        "optional":false
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        )
        .to_string()
        .as_bytes(),
        organisation,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            None,
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
        )
        .await;
    (
        holder_did,
        holder_identifier,
        verifier_did,
        verifier_identifier,
        credential,
        interaction,
        proof,
    )
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vc_similar_names() {
    let mock_server = MockServer::start().await;
    let config = fixtures::create_config(mock_server.uri(), None);
    let db_conn = fixtures::create_db(&config).await;
    let organisation = fixtures::create_organisation(&db_conn).await;
    let issuer_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let issuer_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(issuer_did.clone()),
            ..Default::default()
        }),
    )
    .await;
    let verifier_did = fixtures::create_did(&db_conn, &organisation, None).await;
    let verifier_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(verifier_did.clone()),
            ..Default::default()
        }),
    )
    .await;

    let holder_key = fixtures::create_key(
        &db_conn,
        &organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
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
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &db_conn,
        &organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".to_string()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key,
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = fixtures::create_identifier(
        &db_conn,
        &organisation,
        Some(TestingIdentifierParams {
            did: Some(holder_did.clone()),
            ..Default::default()
        }),
    )
    .await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = create_credential_schema_with_claims(
        &db_conn,
        "Schema1",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let credential = fixtures::create_credential(
        &db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        &issuer_identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams {
            holder_identifier: Some(holder_identifier),
            credential: Some("TOKEN"),
            role: Some(CredentialRole::Holder),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = mock_server.uri();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let _handle = run_server(listener, config, &db_conn).await;

    let claims = credential.claims.clone().unwrap();
    let interaction = fixtures::create_interaction(
        &db_conn,
        &verifier_url,
        json!(
            {
                "response_type":"vp_token",
                "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
                "nonce":"QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
                "client_id_scheme":"redirect_uri",
                "client_id": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "client_metadata":
                {
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
                    "vp_formats":
                    {
                        "jwt_vp_json":
                        {
                            "alg":["EdDSA"]
                        },
                        "jwt_vc_json":{
                            "alg":["EdDSA"]
                        },
                        "ldp_vp":{
                            "proof_type":["DataIntegrityProof"]
                        },
                        "mso_mdoc":{
                            "alg":["EdDSA"]
                        },
                        "vc+sd-jwt": {
                            "kb-jwt_alg_values": ["EdDSA", "ES256"],
                            "sd-jwt_alg_values": ["EdDSA", "ES256"]
                        }
                    },
                    "client_id_scheme":"redirect_uri"
                },
                "response_mode":"direct_post",
                "response_uri": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "presentation_definition":
                {
                    "id":"fa42f6f7-f1a7-4af6-aa0e-970468cc4b3f",
                    "input_descriptors":
                    [
                        {
                            "format": {
                                "jwt_vc_json": {
                                    "alg": ["EdDSA", "ES256"]
                                }
                            },
                            "id":"input_0",
                            "constraints":{
                                "fields":[
                                    {
                                        "path":["$.credentialSchema.id"],
                                        "filter": {
                                            "type": "string",
                                            "const": credential_schema.schema_id
                                        }
                                    },
                                    {
                                        "id": claims[0].id,
                                        "path":["$.vc.credentialSubject.cat"],
                                        "optional":false
                                    },
                                    {
                                        "id": claims[1].id,
                                        "path":["$.vc.credentialSubject.cat2"],
                                        "optional":false
                                    }
                                ]
                            }
                        }
                    ]
                }
            }
        )
        .to_string()
        .as_bytes(),
        &organisation,
    )
    .await;

    let proof = fixtures::create_proof(
        &db_conn,
        &verifier_identifier,
        None,
        None,
        ProofStateEnum::Requested,
        ProofRole::Holder,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        None,
    )
    .await;

    Mock::given(method(Method::POST))
        .and(path("/ssi/openid4vp/draft-20/response".to_owned()))
        // Just sample query params as they are too dynamic and contain random ids
        .and(body_string_contains("state"))
        .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f"))
        .and(body_string_contains("vp_token"))
        .and(body_string_contains("descriptor_map"))
        .and(body_string_contains("input_0"))
        .and(body_string_contains("jwt_vp_json")) // As we use jwt as credential input. Temporary.
        .and(body_string_contains("verifiableCredential"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&mock_server)
        .await;

    // WHEN
    let url = format!("{base_url}/api/interaction/v1/presentation-submit");

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "didId": holder_did.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": [
                credential.claims.unwrap().first().unwrap().id
              ]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .unwrap()
            .iter()
            .any(|claim| claim.claim.path == "cat")
    );
    assert!(
        !proof
            .claims
            .as_ref()
            .unwrap()
            .iter()
            .any(|claim| claim.claim.path == "cat2")
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
    );
    assert_eq!(
        proof.holder_identifier.unwrap().did.unwrap().did,
        holder_did.did
    );
}

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let client_metadata = json!(
    {
        "jwks": {
            "keys": [{
                "crv": "P-256",
                "kid": "not-a-uuid",
                "kty": "EC",
                "x": "cd_LTtCQnat2XnDElumvgQAM5ZcnUMVTkPig458C1yc",
                "y": "iaQmPUgir80I2XCFqn2_KPqdWH0PxMzCCP8W3uPxlUA",
                "use": "enc"
            }]
        },
        "vp_formats":
        {
            "jwt_vp_json":
            {
                "alg":["EdDSA"]
            },
            "jwt_vc_json":{
                "alg":["EdDSA"]
            },
            "ldp_vp":{
                "proof_type":["DataIntegrityProof"]
            },
            "mso_mdoc":{
                "alg":["EdDSA"]
            },
            "vc+sd-jwt": {
                "kb-jwt_alg_values": ["EdDSA", "ES256"],
                "sd-jwt_alg_values": ["EdDSA", "ES256"]
            }
        }
    });

    let (holder_did, _, verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation_dcql(
            &context,
            &organisation,
            &identifier,
            &client_metadata.to_string(),
        )
        .await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
                .and(body_string_contains("state"))
                .and(body_string_contains("53c44733-4f9d-4db2-aa83-afb8e17b500f")) // this is the state
                .and(body_string_contains("vp_token"))
                .and(body_string_contains("input_0"))
        }))
        .await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v1/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "didId": holder_did.id,
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": ["firstName"]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = fixtures::get_proof(&context.db.db_conn, &proof.id).await;
    assert_eq!(proof.state, ProofStateEnum::Accepted);
    assert!(
        proof
            .claims
            .as_ref()
            .unwrap()
            .iter()
            .any(|c| c.claim.value == "test")
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
    );
    assert_eq!(
        proof.holder_identifier.unwrap().did.unwrap().did,
        holder_did.did
    );
    let proof_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await;
    assert_eq!(
        proof_history
            .values
            .first()
            .as_ref()
            .unwrap()
            .target
            .as_ref()
            .unwrap(),
        &verifier_identifier.id.to_string()
    )
}

async fn setup_submittable_presentation_dcql(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
    client_metadata: &str,
) -> (
    Did,
    Identifier,
    Did,
    Identifier,
    Credential,
    Interaction,
    Proof,
) {
    let verifier_key = context
        .db
        .keys
        .create(organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![
                    RelatedKey {
                        role: KeyRole::Authentication,
                        key: verifier_key.clone(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let holder_key = fixtures::create_key(
        &context.db.db_conn,
        organisation,
        Some(TestingKeyParams {
            key_type: Some("ECDSA".to_string()),
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
        }),
    )
    .await;
    let holder_did = fixtures::create_did(
        &context.db.db_conn,
        organisation,
        Some(TestingDidParams {
            did_method: Some("KEY".to_string()),
            did: Some(
                "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                    .parse()
                    .unwrap(),
            ),
            keys: Some(vec![RelatedKey {
                role: KeyRole::Authentication,
                key: holder_key,
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential_schema = fixtures::create_credential_schema(
        &context.db.db_conn,
        organisation,
        Some(TestingCredentialSchemaParams {
            name: Some("Schema1".to_string()),
            ..Default::default()
        }),
    )
    .await;

    let credential = fixtures::create_credential(
        &context.db.db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        issuer_identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams {
            holder_identifier: Some(holder_identifier.clone()),
            role: Some(CredentialRole::Holder),
            credential: Some("TOKEN"),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = context.server_mock.uri();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        &verifier_url,
        json!(
            {
                "response_type":"vp_token",
                "state": "53c44733-4f9d-4db2-aa83-afb8e17b500f",
                "nonce":"QnoICmZxqAUZdOlPJRVtbJrrHJRTDwCM",
                "client_id_scheme":"redirect_uri",
                "client_id": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "client_metadata": client_metadata,
                "response_mode":"direct_post",
                "response_uri": format!("{verifier_url}/ssi/openid4vp/draft-20/response"),
                "dcql_query":
                {
                    "credentials" : [
                        {
                            "id": "input_0",
                            "format": "jwt_vc_json",
                            "meta": {
                                "type_values": [[
                                    "https://www.w3.org/2018/credentials#VerifiableCredential",
                                    format!("{}#Schema1", credential_schema.schema_id)
                                ]]
                            },
                            "claims": [
                                {
                                    "path": ["firstName"]
                                }
                            ]
                        }
                    ]
                }
            }
        )
        .to_string()
        .as_bytes(),
        organisation,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            None,
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT25",
            Some(&interaction),
            verifier_key,
        )
        .await;
    (
        holder_did,
        holder_identifier,
        verifier_did,
        verifier_identifier,
        credential,
        interaction,
        proof,
    )
}
