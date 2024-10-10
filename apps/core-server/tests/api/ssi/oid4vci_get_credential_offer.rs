use one_core::model::credential::CredentialStateEnum;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_offer_success_jwt() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(None, "http://test.com", "NONE".as_bytes(), &organisation)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "OPENID4VC",
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
            "{}/ssi/oidc-issuer/v1/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let offer_credential = &offer["credentials"][0];
    assert_eq!(offer_credential["format"], "jwt_vc_json");
    assert_eq!(offer_credential["wallet_storage_type"], "SOFTWARE");

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        CredentialStateEnum::Pending,
        credential.state.unwrap()[0].state
    );
}

#[tokio::test]
async fn test_get_credential_offer_success_mdoc() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did().await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_nested_claims(
            "test",
            &organisation,
            "NONE",
            TestingCreateSchemaParams {
                format: Some("MDOC".to_string()),
                ..Default::default()
            },
        )
        .await;

    let interaction = context
        .db
        .interactions
        .create(None, "http://test.com", "NONE".as_bytes(), &organisation)
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "OPENID4VC",
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
            "{}/ssi/oidc-issuer/v1/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let offer_credential = &offer["credentials"][0];
    assert_eq!(offer_credential["format"], "mso_mdoc");
    assert_eq!(offer_credential["wallet_storage_type"], "SOFTWARE");

    let expected_claims = serde_json::json!({
      "address": {
        "value": {
          "coordinates": {
            "value": {
              "x": {
                "value": "test",
                "value_type": "NUMBER"
              },
              "y": {
                "value": "test",
                "value_type": "NUMBER"
              }
            },
            "value_type": "OBJECT"
          },
          "street": {
            "value": "test",
            "value_type": "STRING"
          }
        },
        "value_type": "OBJECT"
      }
    });
    assert_eq!(expected_claims, offer_credential["claims"]);
    assert_eq!(credential_schema.schema_id, offer_credential["doctype"]);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(
        CredentialStateEnum::Pending,
        credential.state.unwrap()[0].state
    );
}

#[tokio::test]
async fn test_get_credential_offer_not_found() {
    // GIVEN
    let context = TestContext::new().await;

    // WHEN
    let resp = context
        .api
        .ssi
        .get_credential_offer(Uuid::new_v4(), Uuid::new_v4())
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}
