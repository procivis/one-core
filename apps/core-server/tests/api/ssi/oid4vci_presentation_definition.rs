use serde_json::json;
use uuid::Uuid;

use one_core::model::proof::ProofStateEnum;

use crate::utils::db_clients::proof_schemas::CreateProofInputSchema;
use crate::{fixtures::TestingDidParams, utils::context::TestContext};
use one_core::model::did::{Did, KeyRole, RelatedKey};
use one_core::model::interaction::Interaction;
use one_core::model::key::Key;
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
    pub verifier_key: Key,
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
        }
    });

    let schema_id = Uuid::new_v4();
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_claims(
            &schema_id,
            "NewCredentialSchema",
            &organisation,
            "NONE",
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
        .create("Schema1", &organisation, proof_input_schema)
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
            &organisation,
            TestingDidParams {
                keys: Some(vec![RelatedKey {
                    role: KeyRole::AssertionMethod,
                    key: verifier_key.to_owned(),
                }]),
                ..Default::default()
            },
        )
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
        verifier_did,
        interaction,
        verifier_key,
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
            verifier_key,
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
                        "path": ["$.vc.credentialSubject.cat1"],
                        "optional": false
                    },
                    {
                        "id": new_claim_schemas[1].0,
                        "path": ["$.vc.credentialSubject.cat2"],
                        "optional": false
                    }
                ],
                "validity_credential_nbf": null
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
        verifier_key,
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
            verifier_key,
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
        verifier_key,
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
            verifier_key,
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
