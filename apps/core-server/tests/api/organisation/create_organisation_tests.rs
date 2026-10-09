use one_core::model::history::HistoryAction;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::organisations::{CreateParams, SetOrganisationConfigurationParams};
use crate::utils::context::TestContext;
use crate::utils::db_clients::organisations::TestingOrganisationParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_create_organisation_success_id_set() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4().into();
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            id: Some(organisation_id),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    resp["id"].assert_eq(&organisation_id);

    let history = context
        .db
        .histories
        .get_by_entity_id(&organisation_id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Created
    )
}

#[tokio::test]
async fn test_create_organisation_success_id_not_set() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.organisations.create(Default::default()).await;

    // THEN
    assert_eq!(resp.status(), 201);
    let id = resp.json_value().await["id"].parse();
    context.db.organisations.get(&id).await;
}

#[tokio::test]
async fn test_create_organisation_reject_duplicate_id() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation_id = Uuid::new_v4().into();

    // WHEN
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            id: Some(organisation_id),
            ..Default::default()
        })
        .await;
    let resp2 = context
        .api
        .organisations
        .create(CreateParams {
            id: Some(organisation_id),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    assert_eq!(resp2.status(), 400);
    assert_eq!(resp2.error_code().await, "BR_0023");
}

#[tokio::test]
async fn test_create_organisation_success_with_parent() {
    // GIVEN
    let context = TestContext::new(None).await;
    let parent = context.db.organisations.create().await;

    // WHEN
    let child_id = Uuid::new_v4().into();
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            id: Some(child_id),
            parent_organisation: Some(parent.id),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let stored = context.db.organisations.get(&child_id).await;
    assert_eq!(stored.parent_organisation.unwrap().id(), parent.id);
}

#[tokio::test]
async fn test_create_organisation_fail_non_existing_parent() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            parent_organisation: Some(Uuid::new_v4().into()),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0022");
}

#[tokio::test]
async fn test_create_organisation_fail_parent_already_has_parent() {
    // GIVEN
    let context = TestContext::new(None).await;
    let grandparent = context.db.organisations.create().await;
    let parent = context
        .db
        .organisations
        .create_with(TestingOrganisationParams {
            parent_organisation: Some(grandparent.id),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            parent_organisation: Some(parent.id),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0419");
}

#[tokio::test]
async fn test_create_organisation_fail_self_as_parent() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN - id and parent_organisation both refer to the same (not-yet-existing) organisation.
    let id = Uuid::new_v4().into();
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            id: Some(id),
            parent_organisation: Some(id),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0419");
}

#[tokio::test]
async fn test_create_organisation_with_configuration() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .create(CreateParams {
            configuration: Some(SetOrganisationConfigurationParams {
                selected_ecosystems: Some(vec!["EUDI".into()]),
                enforce_ecosystem_as_issuer: Some(false),
                enforce_ecosystem_as_holder: Some(true),
                enforce_ecosystem_as_verifier: None,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let resp = resp.json_value().await;
    let organisation_id = Uuid::parse_str(resp["id"].as_str().unwrap())
        .unwrap()
        .into();

    let organisation = context.db.organisations.get(&organisation_id).await;
    assert_eq!(
        organisation.configuration.selected_ecosystems,
        vec!["EUDI".into()]
    );
    assert_eq!(
        organisation.configuration.enforce_ecosystem_as_issuer,
        false
    );
    assert_eq!(organisation.configuration.enforce_ecosystem_as_holder, true);
    assert_eq!(
        organisation.configuration.enforce_ecosystem_as_verifier,
        false
    );
}
