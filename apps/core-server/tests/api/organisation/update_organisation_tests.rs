use std::collections::HashSet;

use maplit::hashset;
use one_core::model::history::HistoryAction;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::organisations::{
    ProviderParams, SetOrganisationConfigurationParams, UpdateParams,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::organisations::TestingOrganisationParams;

#[tokio::test]
async fn test_update_organisation_fail_not_existing() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let organisation_id = Uuid::new_v4();
    let resp = context
        .api
        .organisations
        .update(
            &organisation_id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    issuer: None,
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0022");
}

#[tokio::test]
async fn test_update_organisation_success_existing() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let organisation = context.db.organisations.get(&organisation.id).await;
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
async fn test_update_organisation_with_deactivate() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                deactivate: Some(true),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated_organisation = context.db.organisations.get(&organisation.id).await;
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
async fn test_update_organisation_reactivate_deactivated() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // Deactivate the organisation first
    context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                deactivate: Some(true),
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // WHEN - Reactivate the organisation
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                deactivate: Some(false),
                wallet_provider: Some(None),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let reactivated_organisation = context.db.organisations.get(&organisation.id).await;
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
async fn test_update_organisation_fail_non_existing_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    issuer: Some(Uuid::new_v4().into()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0207");
}

#[tokio::test]
async fn test_update_organisation_success_existing_identifier() {
    // GIVEN
    let (context, org, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    issuer: Some(identifier.id),
                    name: Some("PROCIVIS_ONE".to_string()),
                })),
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
async fn test_update_organisation_fail_org_mismatched_identifier() {
    // GIVEN
    let (context, _, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    issuer: Some(identifier.id),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0285");
}

#[tokio::test]
async fn test_update_organisation_success_wallet_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
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
async fn test_update_organisation_success_set_parent_organisation() {
    // GIVEN
    let context = TestContext::new(None).await;
    let parent = context.db.organisations.create().await;
    let child = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &child.id,
            UpdateParams {
                parent_organisation: Some(Some(parent.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated = context.db.organisations.get(&child.id).await;
    assert_eq!(updated.parent_organisation.unwrap().id(), parent.id);
    let history = context
        .db
        .histories
        .get_by_entity_id(&child.id.into())
        .await;
    assert_eq!(
        history.values.first().unwrap().action,
        HistoryAction::Updated
    );
}

#[tokio::test]
async fn test_update_organisation_success_clear_parent_organisation() {
    // GIVEN
    let context = TestContext::new(None).await;
    let parent = context.db.organisations.create().await;
    let child = context.db.organisations.create().await;
    context
        .api
        .organisations
        .update(
            &child.id,
            UpdateParams {
                parent_organisation: Some(Some(parent.id)),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &child.id,
            UpdateParams {
                parent_organisation: Some(None),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated = context.db.organisations.get(&child.id).await;
    assert_eq!(updated.parent_organisation, None);
}

#[tokio::test]
async fn test_update_organisation_fail_parent_already_has_parent() {
    // GIVEN
    let context = TestContext::new(None).await;
    let grandparent = context.db.organisations.create().await;
    let parent = context.db.organisations.create().await;
    let child = context.db.organisations.create().await;
    // Give `parent` its own parent.
    context
        .api
        .organisations
        .update(
            &parent.id,
            UpdateParams {
                parent_organisation: Some(Some(grandparent.id)),
                ..Default::default()
            },
        )
        .await;

    // WHEN - try to nest `child` under an org that itself has a parent.
    let resp = context
        .api
        .organisations
        .update(
            &child.id,
            UpdateParams {
                parent_organisation: Some(Some(parent.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0419");
    let unchanged = context.db.organisations.get(&child.id).await;
    assert_eq!(unchanged.parent_organisation, None);
}

#[tokio::test]
async fn test_update_organisation_fail_organisation_has_children() {
    // GIVEN
    let context = TestContext::new(None).await;
    let org = context.db.organisations.create().await;
    context
        .db
        .organisations
        .create_with(TestingOrganisationParams {
            parent_organisation: Some(org.id),
            ..Default::default()
        })
        .await;
    let new_parent = context.db.organisations.create().await;

    // WHEN - try to give `org` a parent while it already has children.
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                parent_organisation: Some(Some(new_parent.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0419");
    let unchanged = context.db.organisations.get(&org.id).await;
    assert_eq!(unchanged.parent_organisation, None);
}

#[tokio::test]
async fn test_update_organisation_fail_self_as_parent() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                parent_organisation: Some(Some(organisation.id)),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0419");
}

#[tokio::test]
async fn test_update_organisation_fail_non_existing_parent_organisation() {
    // GIVEN
    let context = TestContext::new(None).await;
    let organisation = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &organisation.id,
            UpdateParams {
                parent_organisation: Some(Some(Uuid::new_v4().into())),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!(resp.error_code().await, "BR_0022");
}

#[tokio::test]
async fn test_update_organisation_success_configuration_partial_update() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN: set both flags
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                configuration: Some(SetOrganisationConfigurationParams {
                    trusted_issuer_required: Some(true),
                    trusted_rp_required: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 204);
    let updated = context.db.organisations.get(&org.id).await;
    assert!(updated.configuration.enforce_ecosystem_as_verifier);
    assert!(updated.configuration.enforce_ecosystem_as_holder);

    // WHEN: only update trustedRpRequired, omitting trustedIssuerRequired
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                configuration: Some(SetOrganisationConfigurationParams {
                    trusted_issuer_required: None,
                    trusted_rp_required: Some(false),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    // THEN: the omitted field keeps its previous value
    assert_eq!(resp.status(), 204);
    let updated = context.db.organisations.get(&org.id).await;
    assert!(updated.configuration.enforce_ecosystem_as_verifier);
    assert!(!updated.configuration.enforce_ecosystem_as_holder);
}

#[tokio::test]
async fn test_update_organisation_fail_configuration_mixed_deprecated_and_new_fields() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                configuration: Some(SetOrganisationConfigurationParams {
                    trusted_rp_required: Some(true),
                    enforce_ecosystem_as_issuer: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0480");
    let updated = context.db.organisations.get(&org.id).await;
    assert!(!updated.configuration.enforce_ecosystem_as_issuer);
    assert!(!updated.configuration.enforce_ecosystem_as_holder);
}

#[tokio::test]
async fn test_update_organisation_fail_non_existing_wallet_provider() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("INVALID_VALUE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0430");
}

#[tokio::test]
async fn test_update_organisation_success_wallet_provider_issuer_rotation() {
    // GIVEN
    let (context, org, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 204);

    // WHEN - re-send the same provider name with a new issuer
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    issuer: Some(identifier.id),
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let org = context.db.organisations.get(&org.id).await;
    assert_eq!(org.wallet_provider, Some("PROCIVIS_ONE".to_string()));
    assert_eq!(org.wallet_provider_issuer, Some(identifier.id));
}

#[tokio::test]
async fn test_update_organisation_fail_wallet_provider_already_associated() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 204);
    let other = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &other.id,
            UpdateParams {
                wallet_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0283");
}

#[tokio::test]
async fn test_update_organisation_success_verifier_provider_issuer_rotation() {
    // GIVEN
    let (context, org, identifier, ..) = TestContext::new_with_certificate_identifier(None).await;
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                verifier_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 204);

    // WHEN - re-send the same provider name with a new issuer
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                verifier_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    issuer: Some(identifier.id),
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let org = context.db.organisations.get(&org.id).await;
    assert_eq!(org.verifier_provider, Some("PROCIVIS_ONE".to_string()));
    assert_eq!(org.verifier_provider_issuer, Some(identifier.id));
}

#[tokio::test]
async fn test_update_organisation_fail_verifier_provider_already_associated() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let resp = context
        .api
        .organisations
        .update(
            &org.id,
            UpdateParams {
                verifier_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;
    assert_eq!(resp.status(), 204);
    let other = context.db.organisations.create().await;

    // WHEN
    let resp = context
        .api
        .organisations
        .update(
            &other.id,
            UpdateParams {
                verifier_provider: Some(Some(ProviderParams {
                    name: Some("PROCIVIS_ONE".to_string()),
                    ..Default::default()
                })),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0465");
}
