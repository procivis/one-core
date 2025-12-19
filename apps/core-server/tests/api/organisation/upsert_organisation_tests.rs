use std::collections::HashSet;

use futures::future::join_all;
use maplit::hashset;
use one_core::model::history::HistoryAction;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::organisations::UpsertParams;
use crate::utils::context::TestContext;

#[tokio::test]
async fn test_upsert_organisation_success_not_existing() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation_id,
            UpsertParams {
                name: Some("name".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let organisation = context.db.organisations.get(&organisation_id.into()).await;
    assert_eq!(organisation.name, "name");
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Created
    )
}

#[tokio::test]
async fn test_upsert_organisation_success_not_existing_parallel_test() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let mut requests = vec![];
    for i in 0..10 {
        let name = format!("name-{}", i);
        requests.push(async {
            let org_id = Uuid::new_v4();
            context
                .api
                .organisations
                .upsert(
                    &org_id,
                    UpsertParams {
                        name: Some(name),
                        ..Default::default()
                    },
                )
                .await
        });
    }
    let responses = join_all(requests).await;

    // THEN
    assert!(responses.iter().all(|resp| resp.status() == 204));
}

#[tokio::test]
async fn test_upsert_organisation_success_existing() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation.id,
            UpsertParams {
                name: Some("name".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(organisation.name, "name");
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    )
}

#[tokio::test]
async fn test_upsert_new_organisation_reject_duplicate_name() {
    // GIVEN
    let context = TestContext::new(None).await;
    let existing_org = context.db.organisations.create().await;

    // WHEN
    let new_org_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .upsert(
            &new_org_id,
            UpsertParams {
                name: Some(existing_org.name.clone()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_upsert_existing_organisation_reject_duplicate_name() {
    // GIVEN
    let context = TestContext::new(None).await;
    let existing_org = context.db.organisations.create().await;
    let existing_org2 = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &existing_org2.id,
            UpsertParams {
                name: Some(existing_org.name.clone()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_upsert_organisation_no_name_does_not_change_name() {
    // GIVEN
    let context = TestContext::new(None).await;
    // WHEN
    let organisation_id = Uuid::new_v4();
    context
        .api
        .organisations
        .upsert(
            &organisation_id,
            UpsertParams {
                name: Some("name".to_string()),
                ..Default::default()
            },
        )
        .await;

    // THEN
    context
        .api
        .organisations
        .upsert(
            &organisation_id,
            UpsertParams {
                ..Default::default()
            },
        )
        .await;

    // THEN
    let organisation = context.db.organisations.get(&organisation_id.into()).await;
    assert_eq!(organisation.name, "name");
    assert_eq!(organisation.deactivated_at, None);
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation_id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Created
    );
}

#[tokio::test]
async fn test_upsert_organisation_with_delete() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation.id,
            UpsertParams {
                deactivate: Some(true),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated_organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(updated_organisation.name, organisation.id.to_string());
    assert!(updated_organisation.deactivated_at.is_some());
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Deactivated
    );
}

#[tokio::test]
async fn test_upsert_organisation_reactivate_deactivated() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // Deactivate the organisation first
    context
        .api
        .organisations
        .upsert(
            &organisation.id,
            UpsertParams {
                name: Some("deactivated_name".to_string()),
                deactivate: Some(true),
                ..Default::default()
            },
        )
        .await;

    // WHEN - Reactivate the organisation
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation.id,
            UpsertParams {
                name: Some("reactivated_name".to_string()),
                deactivate: Some(false),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let reactivated_organisation = context.db.organisations.get(&organisation.id).await;
    assert_eq!(reactivated_organisation.name, "reactivated_name");
    assert!(reactivated_organisation.deactivated_at.is_none());
    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation.id.into())
        .await;

    let actions: HashSet<_> = history
        .values
        .into_iter()
        .take(2)
        .map(|item| item.action)
        .collect();

    assert_eq!(
        actions,
        hashset![HistoryAction::Reactivated, HistoryAction::Updated]
    );
}

#[tokio::test]
async fn test_upsert_organisation_fail_non_existing_identifier() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation.id,
            UpsertParams {
                wallet_provider_issuer: Some(Some(Uuid::new_v4().into())),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0207");
}

#[tokio::test]
async fn test_upsert_organisation_success_existing_identifier() {
    // GIVEN
    let (context, org, _, identifier, _) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &org.id,
            UpsertParams {
                wallet_provider_issuer: Some(Some(identifier.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let org = context.db.organisations.get(&org.id).await;
    assert_eq!(org.wallet_provider_issuer, Some(identifier.id));
    let history = context.db.histories.get_by_entity_id(&org.id.into()).await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}

#[tokio::test]
async fn test_upsert_organisation_fail_org_mismatched_identifier() {
    // GIVEN
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .upsert(
            &organisation_id,
            UpsertParams {
                wallet_provider_issuer: Some(Some(identifier.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0285");
}

#[tokio::test]
async fn test_upsert_organisation_success_wallet_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &org.id,
            UpsertParams {
                wallet_provider: Some(Some("PROCIVIS_ONE".to_string())),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let org = context.db.organisations.get(&org.id).await;
    assert_eq!(org.wallet_provider, Some("PROCIVIS_ONE".to_string()));
    let history = context.db.histories.get_by_entity_id(&org.id.into()).await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}

#[tokio::test]
async fn test_upsert_organisation_fail_non_existing_wallet_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .upsert(
            &org.id,
            UpsertParams {
                wallet_provider: Some(Some("INVALID_VALUE".to_string())),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0284");
}
