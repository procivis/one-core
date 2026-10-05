use one_core::model::credential::{Credential, CredentialStateEnum, CredentialType};
use one_core::model::credential_schema::{CredentialSchema, TransactionCode, TransactionCodeType};
use one_core::model::interaction::InteractionType;
use serde_json::json;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::fixtures::interaction::{IssuerInteractionDataParams, dummy_issuer_interaction_data};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::db_clients::interactions::TestingInteractionParams;
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
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data("token", Default::default())),
                ..Default::default()
            },
        )
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
        .get_credential_offer(credential_schema.id, credential.common.id)
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
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data("token", Default::default())),
                ..Default::default()
            },
        )
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
        .get_credential_offer(credential_schema.id, credential.common.id)
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
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data("token", Default::default())),
                ..Default::default()
            },
        )
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
        .get_credential_offer(credential_schema.id, credential.common.id)
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
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data("token", Default::default())),
                ..Default::default()
            },
        )
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
        .get_credential_offer(credential_schema.id, credential.common.id)
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

/// BATCH_PARENT credential of a SD_JWT_VC + MDOC schema, interaction offering the given formats
async fn multi_format_setup(
    offered_formats: &[&str],
) -> (TestContext, CredentialSchema, Credential) {
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema_id = context
        .db
        .credential_schemas
        .create_with_multiformat("test", &organisation, None)
        .await
        .unwrap();
    let credential_schema = context
        .db
        .credential_schemas
        .get(&credential_schema_id)
        .await;
    let offered_formats = credential_schema
        .formats
        .as_ref()
        .await
        .unwrap()
        .iter()
        .filter(|format| offered_formats.contains(&format.format.to_string().as_str()))
        .map(|format| format.id)
        .collect();

    let interaction = context
        .db
        .interactions
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data(
                    "token",
                    IssuerInteractionDataParams {
                        offered_formats,
                        ..Default::default()
                    },
                )),
                ..Default::default()
            },
        )
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
                r#type: Some(CredentialType::BatchParent),
                ..Default::default()
            },
        )
        .await;

    (context, credential_schema, credential)
}

#[tokio::test]
async fn test_get_credential_offer_multi_format_offers_selected_formats() {
    // GIVEN
    let (context, credential_schema, credential) = multi_format_setup(&["SD_JWT_VC"]).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(credential_schema.id, credential.common.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;
    assert_eq!(offer["credential_configuration_ids"], json!(["sd-jwt_vct"]));
}

#[tokio::test]
async fn test_get_credential_offer_multi_format_offers_all_formats_without_selection() {
    // GIVEN
    let (context, credential_schema, credential) = multi_format_setup(&[]).await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(credential_schema.id, credential.common.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let offer = resp.json_value().await;
    let mut ids: Vec<&str> = offer["credential_configuration_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap())
        .collect();
    ids.sort();
    assert_eq!(ids, ["mdoc_doctype", "sd-jwt_vct"]);
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
        .create(
            &organisation,
            InteractionType::Issuance,
            TestingInteractionParams {
                data: Some(dummy_issuer_interaction_data("token", Default::default())),
                ..Default::default()
            },
        )
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
        .get_credential_offer(credential_schema.id, credential.common.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
