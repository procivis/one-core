use one_core::model::credential::CredentialStateEnum;
use one_core::model::interaction::InteractionType;
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::fixtures::interaction::{InteractionDataParams, dummy_interaction_data};
use crate::utils::context::TestContext;
use crate::utils::db_clients::interactions::TestingInteractionParams;

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
        .issuance_reject(interaction.id)
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
        .issuance_reject(interaction.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Rejected, credential.state);
}
