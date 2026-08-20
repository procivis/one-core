use one_core::model::credential::{CredentialStateEnum, CredentialType};
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use one_core::model::interaction::InteractionType;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_offer_success_jwt() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(&organisation, InteractionType::Issuance, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;

    assert_eq!(
        offer["credential_issuer"],
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}/{}",
            context.config.app.core_base_url, identifier.id, credential_schema.id
        )
    );
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let credential_id = &offer["credential_configuration_ids"][0];

    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id().await.unwrap().as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_success_with_tx_code() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Numeric,
                    length: 4,
                    description: None,
                }),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(&organisation, InteractionType::Issuance, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;

    assert_eq!(
        offer["credential_issuer"],
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}/{}",
            context.config.app.core_base_url, identifier.id, credential_schema.id
        )
    );

    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let tx_code =
        offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["tx_code"]
            .as_object()
            .unwrap();
    tx_code["input_mode"].assert_eq(&"numeric".to_string());
    tx_code["length"].assert_eq(&4);

    let credential_id = &offer["credential_configuration_ids"][0];
    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id().await.unwrap().as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_success_certificate_identifier() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(&organisation, InteractionType::Issuance, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;

    assert_eq!(
        offer["credential_issuer"],
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}/{}",
            context.config.app.core_base_url, identifier.id, credential_schema.id
        )
    );
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let credential_id = &offer["credential_configuration_ids"][0];

    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id().await.unwrap().as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_success_mdoc() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims(
            "test",
            &organisation,
            TestingCreateSchemaParams {
                format: Some("MDOC".into()),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(&organisation, InteractionType::Issuance, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
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
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;

    assert_eq!(
        offer["credential_issuer"],
        format!(
            "{}/ssi/openid4vci/final-1.0/OPENID4VCI_FINAL1/{}/{}",
            context.config.app.core_base_url, identifier.id, credential_schema.id
        )
    );

    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let credential_id = &offer["credential_configuration_ids"][0];

    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id().await.unwrap().as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(Uuid::new_v4(), Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_credential_offer_not_found_batch_item() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(&organisation, InteractionType::Issuance, Default::default())
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                r#type: Some(CredentialType::BatchItem),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(credential_schema.id, credential.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
