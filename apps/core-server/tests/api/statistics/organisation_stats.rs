use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::Identifier;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::ProofStateEnum;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use crate::fixtures;
use crate::fixtures::{TestingCredentialParams, create_proof_schema};
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_organisation_stats_empty() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .statistics
        .organisation_stats(None, OffsetDateTime::now_utc(), org.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["current"]["verificationCount"], 0);
    assert!(resp["previous"].is_null());
}

#[tokio::test]
async fn test_organisation_stats() {
    // GIVEN
    let (context, org, identifier, .., key) =
        TestContext::new_with_certificate_identifier(None).await;
    let now = OffsetDateTime::now_utc();
    dummy_history_data(&context, &org, &identifier, key, OffsetDateTime::now_utc()).await;
    // WHEN
    let one_day = Duration::days(1);
    let resp = context
        .api
        .statistics
        .organisation_stats(Some(now - one_day), now + one_day, org.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 1);
    assert_eq!(resp["current"]["verificationCount"], 1);
    assert_eq!(resp["previous"]["issuanceCount"], 1);
    assert_eq!(resp["previous"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["previous"]["verificationCount"], 0);
}

#[tokio::test]
async fn test_organisation_issuer_stats() {
    // GIVEN
    let (context, org, identifier, .., key) =
        TestContext::new_with_certificate_identifier(None).await;
    let now = OffsetDateTime::now_utc();
    dummy_history_data(&context, &org, &identifier, key, OffsetDateTime::now_utc()).await;
    // WHEN
    let one_day = Duration::days(1);
    let resp = context
        .api
        .statistics
        .organisation_issuer_stats(Some(now - one_day), now + one_day, org.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;

    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["values"][0]["current"]["suspendedCount"], 1);
    assert_eq!(resp["values"][0]["previous"]["suspendedCount"], 0);
    assert_eq!(resp["values"][0]["current"]["issuedCount"], 0);
    assert_eq!(resp["values"][0]["previous"]["issuedCount"], 1);
}

async fn dummy_history_data(
    context: &TestContext,
    org: &Organisation,
    identifier: &Identifier,
    key: Key,
    now: OffsetDateTime,
) {
    let credential_schema = context
        .db
        .credential_schemas
        .create("test", org, None, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Created,
            identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, org, None).await;
    let claim_schema = credential_schema
        .claim_schemas
        .as_ref()
        .unwrap()
        .first()
        .unwrap()
        .to_owned();
    let proof_schema = create_proof_schema(
        &context.db.db_conn,
        "Schema1",
        org,
        &[CreateProofInputSchema {
            claims: vec![CreateProofClaim {
                id: claim_schema.id,
                key: &claim_schema.key,
                required: true,
                data_type: &claim_schema.data_type,
                array: false,
            }],
            credential_schema: &credential_schema,
        }],
    )
    .await;
    let proof = context
        .db
        .proofs
        .create(
            None,
            identifier,
            Some(&proof_schema),
            ProofStateEnum::Created,
            "OPENID4VP_DRAFT20",
            None,
            key,
            None,
            None,
        )
        .await;
    context
        .db
        .histories
        .create(
            org,
            TestingHistoryParams {
                action: Some(HistoryAction::Issued),
                entity_id: Some(credential.id.into()),
                entity_type: Some(HistoryEntityType::Credential),
                created_date: Some(now - Duration::hours(25)),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .histories
        .create(
            org,
            TestingHistoryParams {
                action: Some(HistoryAction::Suspended),
                entity_id: Some(credential.id.into()),
                entity_type: Some(HistoryEntityType::Credential),
                created_date: Some(now),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .histories
        .create(
            org,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(proof.id.into()),
                entity_type: Some(HistoryEntityType::Proof),
                created_date: Some(now - Duration::hours(1)),
                ..Default::default()
            },
        )
        .await;
}
