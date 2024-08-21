use one_core::model::proof::ProofStateEnum;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_retract_existing_proof_for_http_transport() {
    // GIVEN
    let (context, organisation, verifier_did, verifier_key) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = credential_schema
        .claim_schemas
        .get()
        .await
        .unwrap()
        .first()
        .unwrap()
        .schema
        .to_owned();

    let proof_schema = context
        .db
        .proof_schemas
        .create(
            "test",
            &organisation,
            CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            },
        )
        .await;

    let interaction_id = Uuid::new_v4();
    let interaction = context
        .db
        .interactions
        .create(Some(interaction_id), "https://www.procivis.ch", &[])
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &verifier_did,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VP",
            Some(&interaction),
            verifier_key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.retract(&proof.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp: Value = resp.json().await;

    assert_eq!(&json!(proof.id), resp.get("id").unwrap());

    let proof = context.db.proofs.get(&proof.id).await;

    assert_eq!(
        // newer come first in order
        vec![ProofStateEnum::Created, ProofStateEnum::Pending],
        Vec::from_iter(proof.state.unwrap().into_iter().map(|s| s.state))
    );

    assert!(context.db.interactions.get(interaction_id).await.is_none());
}
