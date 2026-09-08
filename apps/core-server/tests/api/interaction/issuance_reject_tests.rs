use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::interaction::InteractionType;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::fixtures::interaction::{
    ConfigurationParams, InteractionDataParams, dummy_interaction_data,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::interactions::TestingInteractionParams;

#[tokio::test]
async fn test_issuance_reject_subset_of_multi_format_offer() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let notification_endpoint = format!(
        "{}/ssi/openid4vci/final-1.0/{}/notification",
        context.server_mock.uri(),
        credential_schema.id
    );

    let first_credential_id = Uuid::new_v4().into();
    let second_credential_id = Uuid::new_v4().into();
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            notification_endpoint: Some(notification_endpoint),
            notification_id: Some("first".to_string()),
            additional_configurations: vec![ConfigurationParams {
                credential_configuration_id: "second".to_string(),
                format: "jwt_vc_json".to_string(),
                notification_id: Some("second".to_string()),
                credential_id: Some(second_credential_id),
            }],
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    for credential_id in [first_credential_id, second_credential_id] {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    id: Some(credential_id),
                    interaction: Some(interaction.to_owned()),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;
    }

    context
        .server_mock
        .ssi_notification_endpoint(credential_schema.id, "second", "123", 1)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, Some(vec![second_credential_id]))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let first = context.db.credentials.get(&first_credential_id).await;
    assert_eq!(CredentialStateEnum::Accepted, first.state);
    let second = context.db.credentials.get(&second_credential_id).await;
    assert_eq!(CredentialStateEnum::Rejected, second.state);
}

#[tokio::test]
async fn test_issuance_reject_batch_parent_rejects_its_items() {
    // GIVEN an accepted batch parent with two items
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            batch_size: Some(2),
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let parent = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                r#type: Some(CredentialType::BatchParent),
                interaction: Some(interaction.to_owned()),
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;
    let item_ids = [Uuid::new_v4().into(), Uuid::new_v4().into()];
    for item_id in item_ids {
        context
            .db
            .credentials
            .create(
                &credential_schema,
                CredentialStateEnum::Accepted,
                &identifier,
                "OPENID4VCI_FINAL1",
                TestingCredentialParams {
                    id: Some(item_id),
                    r#type: Some(CredentialType::BatchItem),
                    parent_id: Some(parent.id),
                    key: Some(key.clone()),
                    ..Default::default()
                },
            )
            .await;
    }

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, Some(vec![parent.id]))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let parent = context.db.credentials.get(&parent.id).await;
    assert_eq!(CredentialStateEnum::Rejected, parent.state);
    for item_id in item_ids {
        let item = context.db.credentials.get(&item_id).await;
        assert_eq!(CredentialStateEnum::Rejected, item.state);
    }
}

#[tokio::test]
async fn test_issuance_reject_openid4vci_notification_not_supported_by_issuer() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(&context, &credential_schema, Default::default());
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.state);
}

#[tokio::test]
async fn test_issuance_reject_openid4vci_with_notification() {
    // GIVEN
    let (context, organisation, _, identifier, key) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction_data = dummy_interaction_data(
        &context,
        &credential_schema,
        InteractionDataParams {
            notification_endpoint: Some(format!(
                "{}/ssi/openid4vci/final-1.0/{}/notification",
                context.server_mock.uri(),
                credential_schema.id
            )),
            notification_id: Some("notification_id".to_string()),
            ..Default::default()
        },
    );
    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(interaction_data),
                ..Default::default()
            },
        )
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                key: Some(key),
                ..Default::default()
            },
        )
        .await;

    context
        .server_mock
        .ssi_notification_endpoint(credential_schema.id, "notification_id", "123", 1)
        .await;

    // WHEN
    let resp = context
        .api
        .interactions
        .issuance_reject(interaction.id, None)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.state);
}
