use std::collections::HashSet;

use one_core::model::credential::CredentialStateEnum;
use one_core::model::did::DidType;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierType;
use one_core::model::trust_list_subscription::TrustListSubscriptionState;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{TestingCredentialParams, TestingDidParams, TestingIdentifierParams};
use crate::utils::api_clients::histories::QueryParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::histories::TestingHistoryParams;
use crate::utils::db_clients::trust_collections::TestTrustCollectionParams;

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
        .create(organisation.clone(), TestingDidParams::default())
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
        .create("schema", &organisation, Default::default())
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
                    entity_id: Some(credential.common.id.into()),
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

#[tokio::test]
async fn test_get_history_list_by_proof_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let proof_id = Uuid::new_v4();
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Accepted),
                entity_id: Some(proof_id.into()),
                entity_type: Some(HistoryEntityType::Proof),
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
                action: Some(HistoryAction::Delivered),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Notification),
                target: Some(proof_id.to_string()),
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
                proof_id: Some(proof_id.into()),
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
async fn test_get_history_list_by_trust_collection_id() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let trust_collection = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("collection".to_string()),
                ..Default::default()
            },
        )
        .await;
    let subscription_1 = context
        .db
        .trust_list_subscriptions
        .create(
            "subscription-1",
            None,
            "LoTE",
            "https://example.com/trust-list/1",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;
    let subscription_2 = context
        .db
        .trust_list_subscriptions
        .create(
            "subscription-2",
            None,
            "LoTE",
            "https://example.com/trust-list/2",
            TrustListSubscriptionState::Active,
            trust_collection.id,
        )
        .await;

    // Another collection with its own subscription - must not be returned
    let other_collection = context
        .db
        .trust_collections
        .create(
            organisation.clone(),
            TestTrustCollectionParams {
                name: Some("other-collection".to_string()),
                ..Default::default()
            },
        )
        .await;
    let other_subscription = context
        .db
        .trust_list_subscriptions
        .create(
            "other-subscription",
            None,
            "LoTE",
            "https://example.com/trust-list/other",
            TrustListSubscriptionState::Active,
            other_collection.id,
        )
        .await;

    // History for the collection itself and both of its subscriptions
    for (entity_id, entity_type) in [
        (
            trust_collection.id.into(),
            HistoryEntityType::TrustCollection,
        ),
        (
            subscription_1.id.into(),
            HistoryEntityType::TrustListSubscription,
        ),
        (
            subscription_2.id.into(),
            HistoryEntityType::TrustListSubscription,
        ),
        // Unrelated entries that must be excluded
        (
            other_collection.id.into(),
            HistoryEntityType::TrustCollection,
        ),
        (
            other_subscription.id.into(),
            HistoryEntityType::TrustListSubscription,
        ),
    ] {
        context
            .db
            .histories
            .create(
                &organisation,
                TestingHistoryParams {
                    action: Some(HistoryAction::Created),
                    entity_id: Some(entity_id),
                    entity_type: Some(entity_type),
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
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                trust_collection_id: Some(trust_collection.id),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);

    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(3, values.len());

    let returned_entity_ids = values
        .iter()
        .map(|value| value["entityId"].as_str().unwrap().to_string())
        .collect::<HashSet<_>>();
    let expected_entity_ids = HashSet::from([
        trust_collection.id.to_string(),
        subscription_1.id.to_string(),
        subscription_2.id.to_string(),
    ]);
    assert_eq!(expected_entity_ids, returned_entity_ids);
}

#[tokio::test]
async fn test_get_history_search_by_credential_schema_name() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_did = context
        .db
        .dids
        .create(organisation.clone(), TestingDidParams::default())
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

    let schema = context
        .db
        .credential_schemas
        .create("UniqueSchemaName", &organisation, Default::default())
        .await;

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
                entity_id: Some(credential.common.id.into()),
                entity_type: Some(HistoryEntityType::Credential),
                ..Default::default()
            },
        )
        .await;

    // Unrelated history entry
    context
        .db
        .histories
        .create(
            &organisation,
            TestingHistoryParams {
                action: Some(HistoryAction::Created),
                entity_id: Some(Uuid::new_v4().into()),
                entity_type: Some(HistoryEntityType::Did),
                ..Default::default()
            },
        )
        .await;

    // WHEN - search by credential schema name with specific type
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                search_text: Some("UniqueSchemaName".to_string()),
                search_type: Some("CREDENTIAL_SCHEMA_NAME".to_string()),
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
async fn test_get_history_search_defaults_to_all() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let issuer_did = context
        .db
        .dids
        .create(organisation.clone(), TestingDidParams::default())
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

    let schema = context
        .db
        .credential_schemas
        .create("SearchableSchema", &organisation, Default::default())
        .await;

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
                entity_id: Some(credential.common.id.into()),
                entity_type: Some(HistoryEntityType::Credential),
                ..Default::default()
            },
        )
        .await;

    // WHEN - search with text only, no type (should default to ALL)
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                search_text: Some("SearchableSchema".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert!(
        !values.is_empty(),
        "Expected search to find history entries matching schema name"
    );
}

#[tokio::test]
async fn test_get_history_search_no_match() {
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

    // WHEN - search for something that doesn't exist
    let resp = context
        .api
        .histories
        .list(
            0,
            10,
            QueryParams {
                organisation_ids: Some(vec![organisation.id]),
                search_text: Some("NonExistentSearchTerm12345".to_string()),
                search_type: Some("CREDENTIAL_SCHEMA_NAME".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let values = resp["values"].as_array().unwrap();
    assert_eq!(0, values.len());
}
