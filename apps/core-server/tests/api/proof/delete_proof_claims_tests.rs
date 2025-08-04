use one_core::model::blob::BlobType;
use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::HistoryAction;
use one_core::model::proof::ProofStateEnum;
use shared_types::EntityId;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_delete_proof_claims_success() {
    // GIVEN
    let (context, organisation, _, identifier, verifier_key) =
        TestContext::new_with_did(None).await;

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

    let credential_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let other_blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![5, 4, 3, 2, 1]),
            r#type: Some(BlobType::Credential),
            ..Default::default()
        })
        .await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            value: Some(vec![1, 2, 3, 4, 5]),
            r#type: Some(BlobType::Proof),
            ..Default::default()
        })
        .await;

    let proof = context
        .db
        .proofs
        .create(
            None,
            &identifier,
            None,
            Some(&proof_schema),
            ProofStateEnum::Pending,
            "OPENID4VP_DRAFT20",
            Some(&interaction),
            verifier_key,
            Some(blob.id),
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                credential_blob_id: Some(credential_blob.id),
                ..Default::default()
            },
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

    let get_credential_blob = context.db.blobs.get(&credential_blob.id).await;
    assert!(get_credential_blob.is_none());

    let get_other_blob = context.db.blobs.get(&other_blob.id).await;
    assert!(get_other_blob.is_some());

    let blob = context.db.blobs.get(&blob.id).await;
    assert!(blob.is_none());
}
