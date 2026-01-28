use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::interaction::{Interaction, InteractionType};
use one_core::model::key::Key;
use one_core::model::proof::ProofStateEnum;
use one_core::model::proof_schema::ProofSchema;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;

pub struct TestContextWithOID4VCIData {
    pub context: TestContext,
    pub new_claim_schemas: Vec<(Uuid, &'static str, bool, &'static str, bool)>,
    pub proof_schema: ProofSchema,
    pub verifier_identifier: Identifier,
    pub interaction: Interaction,
    pub verifier_key: Key,
}

async fn new_test_data() -> TestContextWithOID4VCIData {
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let nonce = "nonce123";
    let new_claim_schemas: Vec<(Uuid, &'static str, bool, &'static str, bool)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING", false),
        (Uuid::new_v4(), "cat2", true, "STRING", false),
    ];
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
        "response_uri": "https://response.uri/",
    });

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "NewCredentialSchema",
            &organisation,
            None,
            &new_claim_schemas,
            "JWT",
            &schema_id.to_string(),
        )
        .await;
    let proof_input_schema =
        CreateProofInputSchema::from((&new_claim_schemas[..], &credential_schema));

    let proof_schema = context
        .db
        .proof_schemas
        .create("Schema1", &organisation, vec![proof_input_schema])
        .await;
    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;
    let verifier_did = context
        .db
        .dids
        .create(
            Some(organisation.clone()),
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                    reference: "1".to_string(),
                }]),
                ..Default::default()
            },
        )
        .await;
    let verifier_identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(verifier_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(verifier_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;
    let interaction = context
        .db
        .interactions
        .create(
            None,
            interaction_data.to_string().as_bytes(),
            &organisation,
            InteractionType::Issuance,
            None,
        )
        .await;

    TestContextWithOID4VCIData {
        context,
        new_claim_schemas,
        proof_schema,
        verifier_identifier,
        interaction,
        verifier_key,
    }
}

#[tokio::test]
async fn test_get_presentation_definition_success() {
    // GIVEN
    let TestContextWithOID4VCIData {
        context,
        new_claim_schemas,
        proof_schema,
        verifier_identifier,
        interaction,
        verifier_key,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
            None,
            None,
        )
        .await;

    // WHEN
    let response = context
        .api
        .ssi
        .get_oidc_verifier_presentation_definition(proof.id)
        .await;

    // THEN
    assert_eq!(response.status(), 200);

    let expected = json!({
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
    });
    assert_eq!(expected, response.json_value().await);
}

#[tokio::test]
async fn test_get_presentation_definition_failed_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let response = context
        .api
        .ssi
        .get_oidc_verifier_presentation_definition(Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn test_get_presentation_definition_failed_wrong_exchange_type() {
    // GIVEN
    let TestContextWithOID4VCIData {
        context,
        proof_schema,
        verifier_identifier,
        interaction,
        verifier_key,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            Some(&proof_schema),
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
            None,
            None,
        )
        .await;

    // WHEN
    let response = context
        .api
        .ssi
        .get_oidc_verifier_presentation_definition(proof.id)
        .await;

    // THEN
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn test_get_presentation_definition_failed_wrong_state() {
    // GIVEN
    let TestContextWithOID4VCIData {
        context,
        proof_schema,
        verifier_identifier,
        interaction,
        verifier_key,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_identifier,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
            None,
            None,
        )
        .await;

    // WHEN
    let response = context
        .api
        .ssi
        .get_oidc_verifier_presentation_definition(proof.id)
        .await;

    // THEN
    assert_eq!(response.status(), 400);
}
