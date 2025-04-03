use one_core::model::credential::CredentialStateEnum;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_offer_success_jwt() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did(None).await;

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
            "OPENID4VCI_DRAFT13",
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
    assert_eq!(offer["issuer_did"], did.did.to_string(),);
    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let credential_id = &offer["credential_configuration_ids"][0];

    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id.as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_success_mdoc() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did(None).await;

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
            "OPENID4VCI_DRAFT13",
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
    assert_eq!(offer["issuer_did"], did.did.to_string(),);

    offer["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]
        .assert_eq(&interaction.id);

    let credential_id = &offer["credential_configuration_ids"][0];

    assert_eq!(
        credential_id.as_str(),
        Some(credential_schema.schema_id.as_str())
    );
}

#[tokio::test]
async fn test_get_credential_offer_with_array_success_mdoc() {
    // GIVEN
    let (context, organisation, did, _) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create_with_array_claims(
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

    let claim_id = credential_schema
        .claim_schemas
        .clone()
        .unwrap()
        .into_iter()
        .find(|claim| claim.schema.key == "namespace/root_array/nested/field")
        .unwrap()
        .schema
        .id;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &did,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![
                    (claim_id.into(), "namespace/root_field", "foo-field"),
                    (
                        claim_id.into(),
                        "namespace/root_array/0/nested/0/field",
                        "foo1",
                    ),
                    (
                        claim_id.into(),
                        "namespace/root_array/0/nested/1/field",
                        "foo2",
                    ),
                    (
                        claim_id.into(),
                        "namespace/root_array/1/nested/0/field",
                        "foo3",
                    ),
                    (
                        claim_id.into(),
                        "namespace/root_array/1/nested/1/field",
                        "foo4",
                    ),
                ]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer(credential_schema.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let metadata = resp.json_value().await;

    let credential_configuration =
        &metadata["credential_configurations_supported"][credential_schema.schema_id];

    let expected_claims = serde_json::json!({
        "namespace": {
            "root_field": {
                "value_type": "string",
                "mandatory": true,
            },
            "root_array": [
                {
                    "nested": [
                        {
                            "field": {
                                "value_type": "string",
                                "mandatory": true,
                            }
                        }
                    ]
                }
            ]
        }
    });
    assert_eq!(expected_claims, credential_configuration["claims"]);

    let credential = context.db.credentials.get(&credential.id).await;
    assert_eq!(CredentialStateEnum::Pending, credential.state);
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
