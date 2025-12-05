use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::credential_schema::CredentialSchema;
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofRole, ProofStateEnum};
use serde_json::{Value, json};
use similar_asserts::assert_eq;
use uuid::Uuid;
use wiremock::MockBuilder;
use wiremock::matchers::body_string_contains;

use crate::fixtures::{
    self, ClaimData, TestingCredentialParams, TestingCredentialSchemaParams, TestingDidParams,
    TestingIdentifierParams, TestingKeyParams, create_credential_schema_with_claims,
};
use crate::utils;
use crate::utils::api_clients::Response;
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;

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

    let (_, _, verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation(
            &context,
            &organisation,
            &identifier,
            &client_metadata.to_string(),
            None,
            None,
            None,
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
            .any(|c| c.claim.value == Some("test".to_string()))
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
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
async fn test_presentation_submit_endpoint_for_openid4vc_array_claim() {
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

    let claim_schema_id = Uuid::new_v4();
    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> =
        vec![(claim_schema_id, "array_claim", true, "STRING", true)];

    let credential_schema = create_credential_schema_with_claims(
        &context.db.db_conn,
        "Schema1",
        &organisation,
        "NONE",
        &new_claim_schemas,
    )
    .await;

    let holder_key = fixtures::create_key(
        &context.db.db_conn,
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
        &context.db.db_conn,
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
                key: holder_key.clone(),
                reference: "1".to_string(),
            }]),
            ..Default::default()
        }),
    )
    .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(holder_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some("TOKEN".as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier.clone()),
                key: Some(holder_key),
                role: Some(CredentialRole::Holder),
                credential_blob_id: Some(blob.id),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim/0".to_string(),
                        value: Some("value1".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: claim_schema_id.into(),
                        path: "array_claim/1".to_string(),
                        value: Some("value2".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;
    let interaction_data = json!(
        {
        "response_type": "vp_token",
        "state": "w6pvDAta2_o3d9pJuy_DAqQMmx1g0MZ0NuDcuF9bht-YXZoBoxduJHvucRZUnrJemDUti_N0lL6Jp38pw5PTYA",
        "nonce": "d7a36f6f-b3a1-456b-b21d-b93e99186552",
        "client_id_scheme": "x509_san_dns",
        "client_id": "eudiw-verifier.eudi.dev.procivis-one.com",
        "client_metadata": {
            "jwks": {
                "keys": [
                    {
                        "kid": "d3c5fcf4-74dd-475e-878f-b4a4fceafefc",
                        "kty": "EC",
                        "alg": "ECDH-ES",
                        "use": "enc",
                        "crv": "P-256",
                        "x": "XG35CK3hEBWkWPIKrmnIk5disRl4QVVD18_c66SN1pY",
                        "y": "qyNRSJ8-bhAjdFuWq4QtgT2ztWnW4QayVSdiCw79XhM"
                    }
                ]
            },
            "vp_formats": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
                },
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": [
                        "ES256"
                    ],
                    "kb-jwt_alg_values": [
                        "ES256"
                    ]
                },
                "mso_mdoc": {
                    "alg": [
                        "ES256"
                    ]
                }
            },
            "authorization_encrypted_response_alg": "ECDH-ES",
            "authorization_encrypted_response_enc": "A128CBC-HS256",
            "id_token_encrypted_response_alg": "RSA-OAEP-256",
            "subject_syntax_types_supported": [
                "urn:ietf:params:oauth:jwk-thumbprint"
            ]
        },
        "response_mode": "direct_post",
        "response_uri": format!("{}/ssi/openid4vp/draft-20/response", context.server_mock.uri()),
        "dcql_query": {
                "credentials": [
                    {
                        "id": "query_0",
                        "format": "jwt_vc_json",
                        "meta": {
                            "type_values": [[credential_schema.id]]
                        },
                        "claims": [
                            {
                                "path": [
                                    "array_claim",
                                    1
                                ]
                            }
                        ]
                    }
                ]
            },
        "verifier_details": {
            "Certificate": {
                "chain": "-----BEGIN CERTIFICATE-----\nMIIDCDCCAq6gAwIBAgIUD6isgv1Gf8SF8ZsaST3DqruZ3+YwCgYIKoZIzj0EAwIw\nXDEeMBwGA1UEAwwVUElEIElzc3VlciBDQSAtIFVUIDAyMS0wKwYDVQQKDCRFVURJ\nIFdhbGxldCBSZWZlcmVuY2UgSW1wbGVtZW50YXRpb24xCzAJBgNVBAYTAlVUMB4X\nDTI1MDYxNzA3MjgwMFoXDTI3MDYxNzA3Mjc1OVowRzEUMBIGA1UEAwwLUHJvY2l2\naXMgQUcxDDAKBgNVBAUTAzAwMTEUMBIGA1UECgwLUHJvY2l2aXMgQUcxCzAJBgNV\nBAYTAlVUMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1wEqLsS+KKpwZ1xzy26B\n8ublugPFQPRekAJla1tD+/L7zFSGRQh6cjnPyaKj5vFqfQkt0wkYLpPFe1UK6i+w\nSqOCAWEwggFdMAwGA1UdEwEB/wQCMAAwHwYDVR0jBBgwFoAUYseURyi9D6IWIKea\nwkmURPEB08cwRQYDVR0RBD4wPIEQcnVzdUBwcm9jaXZpcy5jaIIoZXVkaXctdmVy\naWZpZXIuZXVkaS5kZXYucHJvY2l2aXMtb25lLmNvbTASBgNVHSUECzAJBgcogYxd\nBQEGMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHBzOi8vcHJlcHJvZC5wa2kuZXVkaXcu\nZGV2L2NybC9waWRfQ0FfVVRfMDIuY3JsMB0GA1UdDgQWBBQ7svc9QoDI+c3lu1FI\nOpbYRsWvrjAOBgNVHQ8BAf8EBAMCB4AwXQYDVR0SBFYwVIZSaHR0cHM6Ly9naXRo\ndWIuY29tL2V1LWRpZ2l0YWwtaWRlbnRpdHktd2FsbGV0L2FyY2hpdGVjdHVyZS1h\nbmQtcmVmZXJlbmNlLWZyYW1ld29yazAKBggqhkjOPQQDAgNIADBFAiEA6t35rTiQ\nSPnyEm2DmktSUqkv0/tSyaX/nxkf448aVDACIFA88bVq5ryMyaKiX6dmqK3bUvga\nhEAq2cdJl8t98DjK\n-----END CERTIFICATE-----\n",
                "fingerprint": "90963d9afbed123cf2ff445ba828f81a4ac03b0061123d360e0a4e3ca1b75dac",
                "expiry": [
                    2027,
                    168,
                    7,
                    27,
                    59,
                    0,
                    0,
                    0,
                    0
                ]
            }
        }
    });

    let (_, _, verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation(
            &context,
            &organisation,
            &identifier,
            &client_metadata.to_string(),
            Some(credential_schema),
            Some(credential.clone()),
            Some(interaction_data),
        )
        .await;

    context
        .server_mock
        .ssi_request_uri_endpoint(Some(|mock_builder: MockBuilder| {
            // Just sample query params as they are too dynamic and contain random ids
            mock_builder
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
          "submitCredentials": {
            "query_0": {
              "credentialId": credential.id,
              "submitClaims": [
                "query_0:array_claim/1"
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
            .any(|c| c.claim.value == Some("value2".to_string()))
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
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

    let (_, _, verifier_did, _, credential, interaction, proof) = setup_submittable_presentation(
        &context,
        &organisation,
        &identifier,
        &client_metadata.to_string(),
        None,
        None,
        None,
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
            .any(|c| c.claim.value == Some("test".to_string()))
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
    );
}

async fn setup_submittable_presentation(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
    client_metadata: &str,
    credential_schema: Option<CredentialSchema>,
    credential: Option<Credential>,
    interaction_data: Option<Value>,
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
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
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

    let credential_schema = match credential_schema {
        None => {
            fixtures::create_credential_schema(
                &context.db.db_conn,
                organisation,
                Some(TestingCredentialSchemaParams {
                    name: Some("Schema1".to_string()),
                    ..Default::default()
                }),
            )
            .await
        }
        Some(schema) => schema,
    };

    let (holder_did, holder_identifier, credential) = match credential {
        None => {
            let holder_key = fixtures::create_key(
                &context.db.db_conn,
                organisation,
                Some(TestingKeyParams {
                    key_type: Some("ECDSA".to_string()),
                    storage_type: Some("INTERNAL".to_string()),
                    public_key: Some(vec![
                        2, 41, 83, 61, 165, 86, 37, 125, 46, 237, 61, 7, 255, 169, 76, 11, 51, 20,
                        151, 189, 221, 246, 169, 103, 136, 2, 114, 144, 254, 4, 26, 202, 33,
                    ]),
                    key_reference: Some(vec![
                        214, 40, 173, 242, 210, 229, 35, 49, 245, 164, 136, 170, 0, 0, 0, 0, 0, 0,
                        0, 32, 168, 61, 62, 181, 162, 142, 116, 226, 190, 20, 146, 183, 17, 166,
                        110, 17, 207, 54, 243, 166, 143, 172, 23, 72, 196, 139, 42, 147, 222, 122,
                        234, 133, 236, 18, 64, 113, 85, 218, 233, 136, 236, 48, 86, 184, 249, 54,
                        210, 76,
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
                        key: holder_key.clone(),
                        reference: "1".to_string(),
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

            let blob = context
                .db
                .blobs
                .create(TestingBlobParams {
                    value: Some("TOKEN".as_bytes().to_vec()),
                    ..Default::default()
                })
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
                    credential_blob_id: Some(blob.id),
                    key: Some(holder_key),
                    ..Default::default()
                },
            )
            .await;
            (holder_did, holder_identifier, credential)
        }
        Some(credential) => (
            credential.holder_identifier.clone().unwrap().did.unwrap(),
            credential.holder_identifier.clone().unwrap(),
            credential,
        ),
    };

    let verifier_url = context.server_mock.uri();
    let claims = credential.claims.clone().unwrap();
    let interaction_data = interaction_data.unwrap_or(json!(
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
    ));
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
        interaction_data.to_string().as_bytes(),
        organisation,
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT25",
            Some(&interaction),
            verifier_key,
            None,
            None,
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
    let (context, organisation, _, issuer_identifier, ..) = TestContext::new_with_did(None).await;

    let verifier_did = context
        .db
        .dids
        .create(Some(organisation.to_owned()), Default::default())
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                ..Default::default()
            },
        )
        .await;

    let holder_key = fixtures::create_key(
        &context.db.db_conn,
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
    let holder_did = context
        .db
        .dids
        .create(
            Some(organisation.to_owned()),
            TestingDidParams {
                did_method: Some("KEY".to_string()),
                did: Some(
                    "did:key:zDnaeTDHP1rEYDFKYtQtH9Yx6Aycyxj7y9PXYDSeDKHnWUFP6"
                        .parse()
                        .unwrap(),
                ),
                keys: Some(vec![RelatedKey {
                    role: KeyRole::Authentication,
                    key: holder_key.clone(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let holder_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(holder_did.to_owned()),
                is_remote: Some(false),
                ..Default::default()
            },
        )
        .await;

    let new_claim_schemas: Vec<(Uuid, &str, bool, &str, bool)> = vec![
        (Uuid::new_v4(), "cat", true, "STRING", false), // Presentation 2 token 1
        (Uuid::new_v4(), "cat2", false, "STRING", false), // Optional - not provided
    ];

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &Uuid::new_v4(),
            "Schema1",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
            "Schema1",
        )
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some("TOKEN".as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer_identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                holder_identifier: Some(holder_identifier),
                key: Some(holder_key),
                credential_blob_id: Some(blob.id),
                role: Some(CredentialRole::Holder),
                claims_data: Some(
                    new_claim_schemas
                        .into_iter()
                        .map(|(id, name, _, _, _)| ClaimData {
                            schema_id: id.into(),
                            path: name.to_string(),
                            value: Some(name.to_string()),
                            selectively_disclosable: true,
                        })
                        .collect(),
                ),
                ..Default::default()
            },
        )
        .await;

    let verifier_url = context.server_mock.uri();
    let base_url = &context.api.base_url;

    let claims = credential.claims.clone().unwrap();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
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
                                        "optional":true
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
        InteractionType::Verification,
    )
    .await;

    let proof = fixtures::create_proof(
        &context.db.db_conn,
        &verifier_identifier,
        None,
        ProofStateEnum::Requested,
        ProofRole::Holder,
        "OPENID4VP_DRAFT20",
        Some(&interaction),
        None,
        None,
        None,
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
    let url = format!("{base_url}/api/interaction/v1/presentation-submit");

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
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

    let (_, _, verifier_did, verifier_identifier, credential, interaction, proof) =
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
          "submitCredentials": {
            "input_0": {
              "credentialId": credential.id,
              "submitClaims": ["input_0:firstName"]
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
            .any(|c| c.claim.value == Some("test".to_string()))
    );
    assert_eq!(
        proof.verifier_identifier.unwrap().did.unwrap().did,
        verifier_did.did
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
                        reference: "1".to_string(),
                    },
                    RelatedKey {
                        role: KeyRole::AssertionMethod,
                        key: verifier_key.clone(),
                        reference: "1".to_string(),
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
                key: holder_key.clone(),
                reference: "1".to_string(),
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

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some("TOKEN".as_bytes().to_vec()),
            ..Default::default()
        })
        .await;

    let credential = fixtures::create_credential(
        &context.db.db_conn,
        &credential_schema,
        CredentialStateEnum::Accepted,
        issuer_identifier,
        "OPENID4VCI_DRAFT13",
        TestingCredentialParams {
            holder_identifier: Some(holder_identifier.clone()),
            key: Some(holder_key),
            role: Some(CredentialRole::Holder),
            credential_blob_id: Some(blob.id),
            ..Default::default()
        },
    )
    .await;

    let verifier_url = context.server_mock.uri();
    let interaction = fixtures::create_interaction(
        &context.db.db_conn,
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
        InteractionType::Verification,
    )
    .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            None,
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT25",
            Some(&interaction),
            verifier_key,
            None,
            None,
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
async fn test_presentation_submit_endpoint_empty() {
    let context = TestContext::new(None).await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v1/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": Uuid::new_v4(),
          "submitCredentials": {}
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(Response::from(resp).error_code().await, "BR_0246")
}
