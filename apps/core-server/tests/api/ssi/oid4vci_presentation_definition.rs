use serde_json::json;
use uuid::Uuid;

use one_core::model::proof::ProofStateEnum;

use crate::{fixtures::TestingDidParams, utils::context::TestContext};
use one_core::model::did::Did;
use one_core::model::interaction::Interaction;
use one_core::model::organisation::Organisation;
use one_core::model::proof_schema::ProofSchema;

pub struct TestContextWithOID4VCIData {
    pub context: TestContext,
    pub organisation: Organisation,
    pub new_claim_schemas: Vec<(Uuid, &'static str, bool, &'static str)>,
    pub interaction_data: serde_json::Value,
    pub proof_schema: ProofSchema,
    pub verifier_did: Did,
    pub interaction: Interaction,
}

async fn new_test_data() -> TestContextWithOID4VCIData {
    let (context, organisation) = TestContext::new_with_organisation().await;

    let nonce = "nonce123";
    let new_claim_schemas: Vec<(Uuid, &'static str, bool, &'static str)> = vec![
        (Uuid::new_v4(), "cat1", true, "STRING"),
        (Uuid::new_v4(), "cat2", true, "STRING"),
    ];
    let interaction_data = json!({
        "nonce": nonce,
        "presentation_definition": {
            "id": "75fcc8e1-a14c-4509-9831-993c5fb37e26",
            "input_descriptors": [{
                "id": "input_0",
                "constraints": {
                    "fields": [
                        {
                            "id": new_claim_schemas[0].0,
                            "path": ["$.credentialSubject.cat1"],
                            "optional": false
                        },
                        {
                            "id": new_claim_schemas[1].0,
                            "path": ["$.credentialSubject.cat2"],
                            "optional": false
                        }
                    ]
                }
            }]
        }
    });

    context
        .db
        .credential_schemas
        .create_with_claims(
            "NewCredentialSchema",
            &organisation,
            "NONE",
            &new_claim_schemas,
            "JWT",
        )
        .await;
    let proof_schema = context
        .db
        .proof_schemas
        .create("Schema1", &organisation, &new_claim_schemas)
        .await;
    let verifier_did = context
        .db
        .dids
        .create(&organisation, TestingDidParams::default())
        .await;
    let interaction = context
        .db
        .interactions
        .create(
            None,
            &context.server_mock.uri(),
            interaction_data.to_string().as_bytes(),
        )
        .await;

    TestContextWithOID4VCIData {
        context,
        organisation,
        new_claim_schemas,
        interaction_data,
        proof_schema,
        verifier_did,
        interaction,
    }
}

#[tokio::test]
async fn test_get_presentation_definition_success() {
    // GIVEN
    let TestContextWithOID4VCIData {
        context,
        new_claim_schemas,
        proof_schema,
        verifier_did,
        interaction,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
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
            "id": "input_0",
            "constraints": {
                "fields": [
                    {
                        "id": new_claim_schemas[0].0,
                        "path": ["$.credentialSubject.cat1"],
                        "optional": false
                    },
                    {
                        "id": new_claim_schemas[1].0,
                        "path": ["$.credentialSubject.cat2"],
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
    let context = TestContext::new().await;

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
async fn test_get_presentation_definition_failed_wrong_transport_type() {
    // GIVEN
    let TestContextWithOID4VCIData {
        context,
        proof_schema,
        verifier_did,
        interaction,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Requested,
            "PROCIVIS_TEMPORARY",
            Some(&interaction),
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
        verifier_did,
        interaction,
        ..
    } = new_test_data().await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VC",
            Some(&interaction),
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
