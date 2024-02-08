use crate::utils::context::TestContext;
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use uuid::Uuid;

fn create_interaction_data() -> serde_json::Value {
    json!({
        "response_type": "vp_token",
        "state": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
        "nonce": "xKpt9wiB4apJ1MVTzQv1zdDty2dVWkl7",
        "client_id_scheme": "redirect_uri",
        "client_id": "http://0.0.0.0:3000/ssi/oidc-verifier/v1/response",
        "client_metadata": {
            "vp_formats": {
                "vc+sd-jwt": {
                    "alg": [
                        "EdDSA"
                    ]
                },
                "jwt_vp_json": {
                    "alg": [
                        "EdDSA"
                    ]
                },
                "jwt_vc_json": {
                    "alg": [
                        "EdDSA"
                    ]
                }
            },
            "client_id_scheme": "redirect_uri"
        },
        "response_mode": "direct_post",
        "response_uri": "http://0.0.0.0:3000/ssi/oidc-verifier/v1/response",
        "presentation_definition": {
            "id": "4ae7e7d5-2ac5-4325-858f-d93ff1fb4f8b",
            "input_descriptors": [
                {
                    "id": "input_0",
                    "constraints": {
                        "fields": [
                            {
                                "id": "2c99eaf6-1b23-4554-afb5-464f92103bf3",
                                "path": [
                                    "$.vc.credentialSubject.firstName"
                                ],
                                "optional": false
                            }
                        ]
                    }
                }
            ]
        }
    })
}

#[tokio::test]
async fn test_get_client_metadata() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    let interaction_id = Uuid::new_v4();
    let interaction_data = create_interaction_data();

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            "http://test.com",
            &interaction_data.to_string().into_bytes(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VC",
            Some(&interaction),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp, interaction_data["client_metadata"]);
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_unknown_proof_id() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_wrong_transport_protocol() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    let interaction_id = Uuid::new_v4();
    let interaction_data = create_interaction_data();

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            "http://test.com",
            &interaction_data.to_string().into_bytes(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "PROCIVIS_TEMPORARY",
            Some(&interaction),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_to_get_client_metadata_wrong_proof_state() {
    // GIVEN
    let (context, organisation, did) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE")
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            &[(
                claim_schema.id,
                &claim_schema.key,
                true,
                &claim_schema.data_type,
            )],
        )
        .await;

    let interaction_id = Uuid::new_v4();
    let interaction_data = create_interaction_data();

    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            "http://test.com",
            &interaction_data.to_string().into_bytes(),
        )
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Rejected,
            "OPENID4VC",
            Some(&interaction),
        )
        .await;

    // WHEN
    let resp = context.api.ssi.get_client_metadata(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}
