use one_core::model::credential::{Credential, CredentialRole, CredentialStateEnum};
use one_core::model::did::{Did, DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::organisation::Organisation;
use one_core::model::proof::{Proof, ProofStateEnum};
use serde_json::json;
use similar_asserts::assert_eq;
use wiremock::MockBuilder;
use wiremock::matchers::body_string_contains;

use crate::fixtures::{
    TestingCredentialParams, TestingCredentialSchemaParams, TestingDidParams,
    TestingIdentifierParams, TestingKeyParams,
};
use crate::utils::api_clients::Response;
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::{fixtures, utils};

#[tokio::test]
async fn test_presentation_submit_endpoint_for_openid4vp_dcql() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let (_, _, verifier_did, verifier_identifier, credential, interaction, proof) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier).await;

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
        "{}/api/interaction/v2/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submission": {
            "input_0": {
              "credentialId": credential.id
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
    // There is no longer a single holder identifier associated with the proof
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
async fn test_presentation_submit_endpoint_user_selection_unknown_claim() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let (_, _, _, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier).await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v2/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submission": {
            "input_0": {
              "credentialId": credential.id,
              "userSelections": ["unknown_claim"]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(Response::from(resp).error_code().await, "BR_0291")
}

#[tokio::test]
async fn test_presentation_submit_endpoint_user_selection_duplicate_claim() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let (_, _, _, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier).await;

    // WHEN
    let url = format!(
        "{}/api/interaction/v2/presentation-submit",
        context.config.app.core_base_url
    );

    let resp = utils::client()
        .post(url)
        .bearer_auth("test")
        .json(&json!({
          "interactionId": interaction.id,
          "submission": {
            "input_0": {
              "credentialId": credential.id,
              "userSelections": ["duplicate", "duplicate"]
            }
          }
        }))
        .send()
        .await
        .unwrap();

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(Response::from(resp).error_code().await, "BR_0291")
}

#[tokio::test]
async fn test_presentation_submit_incompatible_version() {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let (_, _, _, _, credential, interaction, _) =
        setup_submittable_presentation_dcql(&context, &organisation, &identifier).await;

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
    assert_eq!(resp.status(), 400);
    assert_eq!(Response::from(resp).error_code().await, "BR_0292")
}

async fn setup_submittable_presentation_dcql(
    context: &TestContext,
    organisation: &Organisation,
    issuer_identifier: &Identifier,
) -> (
    Did,
    Identifier,
    Did,
    Identifier,
    Credential,
    Interaction,
    Proof,
) {
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
            "OPENID4VP_FINAL1",
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
