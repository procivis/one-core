use std::ops::Sub;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{DidType, KeyRole, RelatedKey};
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierType;
use one_core::model::proof::ProofStateEnum;
use sql_data_provider::test_utilities::get_dummy_date;
use time::{Duration, OffsetDateTime};

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_run_task_suspend_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 0);
    assert_eq!(resp["updatedCredentialIds"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_run_task_suspend_check_with_update() {
    // GIVEN
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            "BITSTRINGSTATUSLIST",
            Default::default(),
        )
        .await;

    let a_while_ago = OffsetDateTime::now_utc().sub(Duration::seconds(1));

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Suspended,
            &did,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                suspend_end_date: Some(a_while_ago),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.tasks.run("SUSPEND_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalChecks"], 1);
    let credentials = resp["updatedCredentialIds"].as_array().unwrap().to_owned();
    assert_eq!(credentials.len(), 1);
    assert_eq!(
        credentials.first().unwrap().as_str().unwrap(),
        credential.id.to_string()
    );

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(credential.state, CredentialStateEnum::Accepted);
    assert_eq!(credential.suspend_end_date, None);
}

#[tokio::test]
async fn test_run_retain_proof_check_no_update() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_run_retain_proof_check_with_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let claim_schema = &credential_schema.claim_schemas.as_ref().unwrap()[0].schema;

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

    let verifier_key = context
        .db
        .keys
        .create(&organisation, Default::default())
        .await;

    let did = context
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
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            &identifier,
            "OPENID4VCI_DRAFT13",
            Default::default(),
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
            ProofStateEnum::Accepted,
            "OPENID4VP_DRAFT20",
            None,
            verifier_key,
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                created_date: Some(get_dummy_date()),
                entity_id: Some(proof.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
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
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = context.db.proofs.get(&proof.id).await;
    assert!(proof.claims.unwrap().is_empty());

    let credential = context.db.credentials.get(&credential.id).await;
    assert!(credential.claims.unwrap().is_empty());
}
