use one_core::model::credential::CredentialStateEnum;
use one_core::model::interaction::InteractionType;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{ClaimData, TestingCredentialParams, key_to_claim_schema_id};
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_credential_offer_success_jwt() {
    // GIVEN
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://test.com",
            "NONE".as_bytes(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
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
            "{}/ssi/openid4vci/draft-13/{}",
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

    let expected_claims = serde_json::json!({
        "firstName": {
            "value": "test",
            "value_type": "STRING",
        },
        "isOver18": {
            "value": "true",
            "value_type": "BOOLEAN",
        },
    });
    assert_eq!(expected_claims, offer["credential_subject"]["keys"]);
}

#[tokio::test]
async fn test_get_credential_offer_when_enable_credential_preview_false() {
    // GIVEN
    let config = indoc::indoc! {"
      issuanceProtocol:
        OPENID4VCI_DRAFT13:
            params:
              public:
                enableCredentialPreview: false
    "}
    .to_string();

    let (context, organisation, did, identifier, ..) =
        TestContext::new_with_did(Some(config)).await;

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
        .create(
            None,
            "http://test.com",
            "NONE".as_bytes(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let namespace_obj_claim_id = key_to_claim_schema_id("namespace", &credential_schema);
    let root_field_claim_id = key_to_claim_schema_id("namespace/root_field", &credential_schema);
    let array_claim_id = key_to_claim_schema_id("namespace/root_array", &credential_schema);
    let nested_obj_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested", &credential_schema);
    let nested_field_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested/field", &credential_schema);

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: root_field_claim_id,
                        path: "namespace/root_field".to_string(),
                        value: Some("foo-field".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/0/field".to_string(),
                        value: Some("foo1".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: namespace_obj_claim_id,
                        path: "namespace".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/1/field".to_string(),
                        value: Some("foo2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/0/field".to_string(),
                        value: Some("foo3".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/1/field".to_string(),
                        value: Some("foo4".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
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
            "{}/ssi/openid4vci/draft-13/{}",
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

    let expected_claims = serde_json::json!({
            "namespace/root_array/0/nested/0/field": {
                "value_type": "STRING",
            },
            "namespace/root_array/0/nested/1/field": {
                "value_type": "STRING",
            },
            "namespace/root_array/1/nested/0/field": {
                "value_type": "STRING",
            },
            "namespace/root_array/1/nested/1/field": {
                "value_type": "STRING",
            },
            "namespace/root_field": {
                "value_type": "STRING",
            }
    });
    assert_eq!(expected_claims, offer["credential_subject"]["keys"]);
}

#[tokio::test]
async fn test_get_credential_offer_success_certificate_identifier() {
    // GIVEN
    let (context, organisation, identifier, certificate, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, "NONE", Default::default())
        .await;

    let interaction = context
        .db
        .interactions
        .create(
            None,
            "http://test.com",
            "NONE".as_bytes(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
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
            "{}/ssi/openid4vci/draft-13/{}",
            context.config.app.core_base_url, credential_schema.id
        )
    );
    assert_eq!(offer["issuer_certificate"], certificate.chain,);
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
    let (context, organisation, did, identifier, ..) = TestContext::new_with_did(None).await;

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
        .create(
            None,
            "http://test.com",
            "NONE".as_bytes(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
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
            "{}/ssi/openid4vci/draft-13/{}",
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
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;

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
        .create(
            None,
            "http://test.com",
            "NONE".as_bytes(),
            &organisation,
            InteractionType::Issuance,
        )
        .await;

    let root_field_claim_id = key_to_claim_schema_id("namespace/root_field", &credential_schema);
    let array_claim_id = key_to_claim_schema_id("namespace/root_array", &credential_schema);
    let nested_obj_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested", &credential_schema);
    let nested_field_claim_id =
        key_to_claim_schema_id("namespace/root_array/nested/field", &credential_schema);

    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams {
                interaction: Some(interaction.to_owned()),
                claims_data: Some(vec![
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/0/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_obj_claim_id,
                        path: "namespace/root_array/1/nested".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/0".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array/1".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: array_claim_id,
                        path: "namespace/root_array".to_string(),
                        value: None,
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: root_field_claim_id,
                        path: "namespace/root_field".to_string(),
                        value: Some("foo-field".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/0/field".to_string(),
                        value: Some("foo1".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/0/nested/1/field".to_string(),
                        value: Some("foo2".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/0/field".to_string(),
                        value: Some("foo3".to_string()),
                        selectively_disclosable: false,
                    },
                    ClaimData {
                        schema_id: nested_field_claim_id,
                        path: "namespace/root_array/1/nested/1/field".to_string(),
                        value: Some("foo4".to_string()),
                        selectively_disclosable: false,
                    },
                ]),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_draft13(credential_schema.id)
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
