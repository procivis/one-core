use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierType;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::histories::QueryParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;

#[tokio::test]
async fn test_get_history_list_simple() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                ..Default::default()
            },
        )
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
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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
        .create(Some(organisation.clone()), TestingDidParams::default())
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(issuer_did.clone()),
                r#type: Some(IdentifierType::Did),
                is_remote: Some(issuer_did.did_type == DidType::Remote),
                ..Default::default()
            },
        )
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
        .create("schema", &organisation, "NONE", Default::default())
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
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_DRAFT13",
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
        .list(
            0,
            999,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                credential_schema_id: Some(schema.id),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    // Expected history entries:
    // - credential schema CREATED -> 1
    // - for each credential, ISSUED -> 10
    // --> total: 11
    let expected_count = credentials_count + 1;
    assert_eq!(expected_count, values.len());
}

#[tokio::test]
async fn test_get_history_filter_by_entity_types() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
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

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Did),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                entity_types: Some(vec!["CREDENTIAL".to_string(), "PROOF".to_string()]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(2, values.len());
}

#[tokio::test]
async fn test_get_history_filter_by_actions() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Deleted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Credential),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Deactivated),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Did),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Shared),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Proof),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                actions: Some(vec!["DELETED".to_string(), "DEACTIVATED".to_string()]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(2, values.len());
}

#[tokio::test]
async fn test_get_history_filter_by_user() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Deleted),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Credential),
                user: Some("TestUser".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Deactivated),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Did),
                user: Some("TestUser".to_string()),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Shared),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Proof),
                user: Some("TestUser2".to_string()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                users: Some(vec!["TestUser".to_string()]),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(2, values.len());
}

#[tokio::test]
async fn test_get_history_show_system_history() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Credential),
                ..Default::default()
            },
        )
        .await;

    context
        .db
        .histories
        .create_without_organisation(TestingHistoryParams {
            action: Some(HistoryAction::Deactivated),
            entity_id: Some(Uuid::new_v4().into()),
            entity_type: Some(HistoryEntityType::Did),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                show_system_history: Some(true),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(2, values.len());
}
