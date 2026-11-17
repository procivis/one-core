use one_core::model::history::HistoryAction;
use serde_json::json;
use shared_types::ProofSchemaId;
use similar_asserts::assert_eq;

use crate::utils::api_clients::proof_schemas::{
    UpdateProofInputSchemaParams, UpdateProofSchemaParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_update_proof_schema_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "multiformat",
            &organisation,
            TestingCreateSchemaParams {
                formats: Some(vec![
                    ("JWT".into(), "jwt-schema".into()),
                    ("SD_JWT_VC".into(), "sd-jwt-schema".into()),
                ]),
                ..Default::default()
            },
        )
        .await;
    let claim_schema = &credential_schema.claim_schemas.as_ref().await.unwrap()[0];

    let response = context
        .api
        .proof_schemas
        .create_with_multiple_schemas(
            "proof schema",
            organisation.id,
            json!([{
                "credentialSchemaId": credential_schema.id,
                "claimSchemas": [{"id": claim_schema.id, "required": true}],
                "formats": ["SD_JWT_VC"],
            }]),
        )
        .await;
    assert_eq!(response.status(), 201);
    let proof_schema_id: ProofSchemaId =
        serde_json::from_value(response.json_value().await["id"].clone()).unwrap();

    // WHEN
    let response = context
        .api
        .proof_schemas
        .update(
            proof_schema_id,
            UpdateProofSchemaParams {
                expire_duration: Some(3600),
                proof_input_schemas: Some(vec![UpdateProofInputSchemaParams {
                    credential_schema_id: credential_schema.id,
                    formats: vec!["SD_JWT_VC".into(), "JWT".into()],
                }]),
            },
        )
        .await;

    // THEN
    assert_eq!(response.status(), 204);

    let response = context.api.proof_schemas.get(proof_schema_id).await;
    assert_eq!(response.status(), 200);
    let details = response.json_value().await;
    assert_eq!(details["expireDuration"], json!(3600));
    assert_eq!(
        details["proofInputSchemas"][0]["formats"],
        json!(["SD_JWT_VC", "JWT"])
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&proof_schema_id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}
