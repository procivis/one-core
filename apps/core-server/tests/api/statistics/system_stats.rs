use one_core::model::credential::CredentialStateEnum;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::Identifier;
use one_core::model::key::Key;
use one_core::model::organisation::Organisation;
use one_core::model::proof::ProofStateEnum;
use serde_json::json;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use crate::fixtures;
use crate::fixtures::{TestingCredentialParams, create_proof_schema};
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::proof_schemas::{CreateProofClaim, CreateProofInputSchema};

#[tokio::test]
async fn test_system_stats_empty() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .statistics
        .system_stats(None, OffsetDateTime::now_utc(), None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["current"]["activeWalletUnitCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["current"]["sessionTokenCount"], 0);
    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["verificationCount"], 0);
    assert_eq!(
        resp["newestOrganisations"][0]["organisation"],
        org.id.to_string()
    );
    assert_eq!(resp["topIssuers"], json!([]));
    assert_eq!(resp["topVerifiers"], json!([]));
    assert!(resp["previous"].is_null());
}

#[tokio::test]
async fn test_system_stats() {
    // GIVEN
    let (context, org, identifier, .., key) =
        TestContext::new_with_certificate_identifier(None).await;
    let now = add_test_entities(&context, &org, &identifier, key).await;

    let org2 = context.db.organisations.create().await;
    // WHEN
    let resp = context
        .api
        .statistics
        .system_stats(Some(now - Duration::days(1)), now, Some(99))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["current"]["activeWalletUnitCount"], 0);
    assert_eq!(resp["current"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["current"]["sessionTokenCount"], 0);
    assert_eq!(resp["current"]["issuanceCount"], 0);
    assert_eq!(resp["current"]["verificationCount"], 1);
    assert_eq!(resp["previous"]["activeWalletUnitCount"], 0);
    assert_eq!(resp["previous"]["credentialLifecycleOperationCount"], 0);
    assert_eq!(resp["previous"]["sessionTokenCount"], 0);
    assert_eq!(resp["previous"]["issuanceCount"], 1);
    assert_eq!(resp["previous"]["verificationCount"], 0);
    assert_eq!(
        resp["newestOrganisations"][0]["organisation"],
        org2.id.to_string()
    );
    assert_eq!(
        resp["newestOrganisations"][1]["organisation"],
        org.id.to_string()
    );
    assert_eq!(resp["topIssuers"], json!([]));
    assert_eq!(
        resp["topVerifiers"],
        json!([
            {
                "current": 1,
                "previous": 0,
                "organisation":org.id.to_string()
            }
        ])
    );
}

#[tokio::test]
async fn test_system_interaction_stats() {
    // GIVEN
    let (context, org, identifier, .., key) =
        TestContext::new_with_certificate_identifier(None).await;
    let now = add_test_entities(&context, &org, &identifier, key).await;

    // WHEN
    let resp = context
        .api
        .statistics
        .system_interaction_stats(Some(now - Duration::days(1)), now)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["values"][0]["organisationId"], org.id.to_string());
    assert_eq!(resp["values"][0]["current"]["verifiedCount"], 1);
    assert_eq!(resp["values"][0]["previous"]["verifiedCount"], 0);
    assert_eq!(resp["values"][0]["current"]["issuedCount"], 0);
    assert_eq!(resp["values"][0]["previous"]["issuedCount"], 1);
}

#[tokio::test]
async fn test_system_management_stats() {
    // GIVEN
    let (context, org, ..) = TestContext::new_with_certificate_identifier(None).await;
    let now = OffsetDateTime::now_utc();
    let credential_schema =
        fixtures::create_credential_schema(&context.db.db_conn, &org, None).await;
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
        &org,
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
    context
        .db
        .histories
        .create(
            &org,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(credential_schema.id.into()),
                entity_type: Some(HistoryEntityType::CredentialSchema),
                created_date: Some(now - Duration::hours(30)),
                ..Default::default()
            },
        )
        .await;
    for _ in 0..3 {
        context
            .db
            .histories
            .create(
                &org,
                TestingHistoryParams {
                    action: Some(HistoryAction::Created),
                    entity_id: Some(proof_schema.id.into()),
                    entity_type: Some(HistoryEntityType::ProofSchema),
                    created_date: Some(now - Duration::hours(1)),
                    ..Default::default()
                },
            )
            .await;
    }
    // WHEN
    let resp = context
        .api
        .statistics
        .system_management_stats(Some(now - Duration::days(1)), now)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["totalItems"], 1);
    assert_eq!(resp["totalPages"], 1);
    assert_eq!(resp["values"][0]["organisationId"], org.id.to_string());
    assert_eq!(
        resp["values"][0]["current"]["credentialSchemaCreatedCount"],
        0
    );
    assert_eq!(
        resp["values"][0]["previous"]["credentialSchemaCreatedCount"],
        1
    );
    assert_eq!(resp["values"][0]["current"]["proofSchemaCreatedCount"], 3);
    assert_eq!(resp["values"][0]["previous"]["proofSchemaCreatedCount"], 0);
}

async fn add_test_entities(
    context: &TestContext,
    org: &Organisation,
    identifier: &Identifier,
    key: Key,
) -> OffsetDateTime {
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
    let now = OffsetDateTime::now_utc();
    context
        .db
        .histories
        .create(
            org,
            TestingHistoryParams {
                action: Some(HistoryAction::Issued),
                entity_id: Some(credential.id.into()),
                entity_type: Some(HistoryEntityType::Credential),
                created_date: Some(now - Duration::hours(30)),
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
    now
}
