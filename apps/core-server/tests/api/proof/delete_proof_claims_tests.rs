use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::HistoryAction;
use one_core::model::proof::ProofStateEnum;
use shared_types::EntityId;
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_delete_proof_claims_success() {
    // GIVEN
    let (context, organisation, verifier_did, verifier_key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
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
        .await;

    let interaction_id = Uuid::new_v4();
    let interaction = context
        .db
        .interactions
        .create(
            Some(interaction_id),
            "https://www.procivis.ch",
            &[],
            &organisation,
        )
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
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &verifier_did,
            "OPENID4VCI_DRAFT13",
            Default::default(),
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(&proof.id, credential.claims.unwrap())
        .await;

    let credential = context.db.credentials.get(&credential.id).await;
    assert!(!credential.claims.unwrap().is_empty());

    // WHEN
    let resp = context.api.proofs.delete_proof_claims(&proof.id).await;

    // THEN
    assert_eq!(resp.status(), 204);

    let proof = context.db.proofs.get(&proof.id).await;

    let history = context
        .db
        .histories
        .get_by_entity_id(&EntityId::from(proof.id))
        .await;

    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::ClaimsRemoved
    );

    assert_eq!(proof.claims.unwrap().len(), 0);

    let credential = context.db.credentials.get(&credential.id).await;
    assert!(credential.claims.unwrap().is_empty());
}
