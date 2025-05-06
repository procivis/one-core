use one_core::model::history::HistoryAction;
use one_core::model::organisation::Organisation;
use one_core::model::proof::ProofStateEnum;
use one_core::model::proof_schema::ProofSchema;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_delete_proof_created_holder_success() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let interaction = context
        .db
        .interactions
        .create(None, "https://example.com", &[], &organisation)
        .await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            None,
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    assert!(!context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert!(context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());

    let resp = context.api.proofs.get(proof.id).await;
    assert_eq!(resp.status(), 404);
    let resp = context.db.interactions.get(interaction.id).await;
    assert!(resp.is_none());
}

#[tokio::test]
async fn test_delete_proof_accepted_holder_fail() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let interaction = context
        .db
        .interactions
        .create(None, "https://example.com", &[], &organisation)
        .await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            None,
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_delete_proof_created_issuer_success() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let proof_schema = setup_proof_schema(&context, &organisation).await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            None,
            key,
        )
        .await;

    // WHEN
    assert!(!context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert!(context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());

    let resp = context.api.proofs.get(proof.id).await;
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_delete_proof_accepted_issuer_fail() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let proof_schema = setup_proof_schema(&context, &organisation).await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            None,
            key,
        )
        .await;

    // WHEN
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_delete_proof_issuer_requested_to_retracted() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let proof_schema = setup_proof_schema(&context, &organisation).await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Requested,
            "OPENID4VP_DRAFT20",
            None,
            key,
        )
        .await;

    // WHEN
    assert!(!context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    let last_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .first()
        .cloned()
        .unwrap();
    assert_eq!(last_history.action, HistoryAction::Retracted);

    let resp = context.api.proofs.get(proof.id).await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["state"], "RETRACTED");
    assert!(!resp["completedDate"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_delete_non_existing_proof_fail() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.proofs.delete_proof(Uuid::new_v4()).await;

    // THEN
    assert_eq!(resp.status(), 404);
}

async fn setup_proof_schema(context: &TestContext, organisation: &Organisation) -> ProofSchema {
    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims("test", organisation, "NONE", Default::default())
        .await;

    // Select a root claim.
    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

    context
        .db
        .proof_schemas
        .create(
            "test",
            organisation,
            vec![CreateProofInputSchema {
                claims: vec![CreateProofClaim {
                    id: claim_schema.id,
                    key: &claim_schema.key,
                    required: true,
                    data_type: &claim_schema.data_type,
                    array: false,
                }],
                credential_schema: &credential_schema,
                validity_constraint: None,
            }],
        )
        .await
}

#[tokio::test]
async fn test_delete_proof_old_exchange() {
    // GIVEN
    let (context, organisation, did, identifier, key) = TestContext::new_with_did(None).await;

    let proof_schema = setup_proof_schema(&context, &organisation).await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            &did,
            &identifier,
            None,
            None,
            Some(&proof_schema),
            ProofStateEnum::Requested,
            "PROCIVIS_TEMPORARY", // this provider no longer exists
            None,
            key,
        )
        .await;

    // WHEN
    assert!(!context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .is_empty());
    let resp = context.api.proofs.delete_proof(proof.id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    let last_history = context
        .db
        .histories
        .get_by_entity_id(&proof.id.into())
        .await
        .values
        .first()
        .cloned()
        .unwrap();
    assert_eq!(last_history.action, HistoryAction::Retracted);

    let resp = context.api.proofs.get(proof.id).await;
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["state"], "RETRACTED");
    assert!(!resp["completedDate"].as_str().unwrap().is_empty());
}
