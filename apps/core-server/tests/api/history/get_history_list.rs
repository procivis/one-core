use one_core::model::{
    credential::CredentialStateEnum,
    history::{HistoryAction, HistoryEntityType},
};
use uuid::Uuid;

use crate::{
    fixtures::{TestingCredentialParams, TestingDidParams},
    utils::{context::TestContext, db_clients::histories::TestingHistoryParams},
};

#[tokio::test]
async fn test_get_history_list_simple() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Credential),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .histories
        .list(0, 10, &organisation.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(1, values.len());
}

#[tokio::test]
async fn test_get_history_list_schema_joins_credentials() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation().await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(organisation.id.into()),
                entity_type: Some(HistoryEntityType::Organisation),
                ..Default::default()
            },
        )
        .await;

    let issuer_did = context
        .db
        .dids
        .create(&organisation, TestingDidParams::default())
        .await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(issuer_did.id.into()),
                entity_type: Some(HistoryEntityType::Did),
                ..Default::default()
            },
        )
        .await;

    let schema = context
        .db
        .credential_schemas
        .create("schema", &organisation, "NONE")
        .await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(schema.id.into()),
                entity_type: Some(HistoryEntityType::CredentialSchema),
                ..Default::default()
            },
        )
        .await;

    let credentials_count = 10;
    for _ in 0..credentials_count {
        let credential = context
            .db
            .credentials
            .create(
                &schema,
                CredentialStateEnum::Created,
                &issuer_did,
                "PROCIVIS_TEMPORARY",
                TestingCredentialParams::default(),
            )
            .await;
        context
            .db
            .histories
            .create(
                &organisation,
                TestingHistoryParams {
                    action: Some(HistoryAction::Issued),
                    entity_id: Some(credential.id.into()),
                    entity_type: Some(HistoryEntityType::Credential),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .histories
        .list(0, 999, &organisation.id, Some(schema.id))
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    let expected_count = credentials_count + /* credential schema */ 1;
    assert_eq!(expected_count, values.len());
}