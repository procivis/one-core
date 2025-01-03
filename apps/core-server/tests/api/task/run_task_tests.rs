use std::ops::Sub;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::{KeyRole, RelatedKey};
use one_core::model::proof::ProofStateEnum;
use time::{Duration, OffsetDateTime};

use crate::fixtures::{TestingCredentialParams, TestingDidParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_run_task_suspend_check_no_update() {
    // GIVEN
    let context = TestContext::new().await;

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
    let (context, organisation, did, _) = TestContext::new_with_did().await;
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
            "OPENID4VC",
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
    let credential_state = &credential.state.unwrap()[0];
    assert_eq!(credential_state.state, CredentialStateEnum::Accepted);
    assert_eq!(credential_state.suspend_end_date, None);
}

#[tokio::test]
async fn test_run_retain_proof_check_no_update() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);
}

#[tokio::test]
async fn test_run_retain_proof_check_with_update() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;

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

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            &did,
            "OPENID4VC",
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
            "OPENID4VC",
            None,
            verifier_key,
        )
        .await;

    context
        .db
        .proofs
        .set_proof_claims(&proof.id, credential.claims.unwrap())
        .await;

    // WHEN
    let resp = context.api.tasks.run("RETAIN_PROOF_CHECK").await;

    // THEN
    assert_eq!(resp.status(), 200);

    let proof = context.db.proofs.get(&proof.id).await;
    assert!(proof.claims.unwrap().is_empty());
}
