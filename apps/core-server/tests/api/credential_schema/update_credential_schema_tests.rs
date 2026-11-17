use one_core::model::credential::CredentialStateEnum;
use one_core::model::credential_schema::{TransactionCode, TransactionCodeType};
use one_core::model::history::HistoryAction;
use one_core::model::localized_text::LocalizedTextField;
use serde_json::json;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::credential_schemas::TestingCreateSchemaParams;

#[tokio::test]
async fn test_update_credential_schema_success() {
    // GIVEN
    let (context, organisation, _, identifier, ..) = TestContext::new_with_did(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                batch_size: Some(5),
                ..Default::default()
            },
        )
        .await;
    let claim_schema_id = credential_schema.claim_schemas.as_ref().await.unwrap()[0].id;
    let pending = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Pending,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;
    let accepted = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &identifier,
            "OPENID4VCI_DRAFT13",
            TestingCredentialParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({
                "batchSize": 3,
                "expiration": 3600,
                "claims": [{
                    "id": claim_schema_id,
                    "translations": { "name": { "de": "Vorname" } }
                }],
                "embeddedDisclosurePolicy": { "policy": "none", "description": "open" },
                "layoutProperties": {
                    "background": { "color": "#ffffff" },
                    "primaryAttribute": "firstName"
                },
                "transactionCode": { "type": "NUMERIC", "length": 6 },
                "translations": {
                    "name": { "de": "Testschema" },
                    "description": { "en": "Updated" }
                }
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let updated = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    assert_eq!(updated.batch_size, Some(3));
    assert_eq!(updated.expiration, Some(Duration::seconds(3600)));
    assert_eq!(
        updated.transaction_code,
        Some(TransactionCode {
            r#type: TransactionCodeType::Numeric,
            length: 6,
            description: None,
        })
    );
    assert!(updated.embedded_disclosure_policy.is_some());
    assert_eq!(
        updated.layout_properties.unwrap().primary_attribute,
        Some("firstName".to_string())
    );

    let schema_texts = context.db.localized_text.get(credential_schema.id).await;
    assert!(schema_texts.iter().any(|t| {
        t.field == LocalizedTextField::Name && t.lang == "de" && t.value == "Testschema"
    }));
    assert!(schema_texts.iter().any(|t| {
        t.field == LocalizedTextField::Description && t.lang == "en" && t.value == "Updated"
    }));
    let claim_texts = context.db.localized_text.get(claim_schema_id).await;
    assert!(
        claim_texts
            .iter()
            .any(|t| t.lang == "de" && t.value == "Vorname")
    );

    let pending = context.db.credentials.get(&pending.common().id).await;
    assert_eq!(
        pending.common().state,
        CredentialStateEnum::InteractionExpired
    );
    let accepted = context.db.credentials.get(&accepted.common().id).await;
    assert_eq!(accepted.common().state, CredentialStateEnum::Accepted);

    let history = context
        .db
        .histories
        .get_by_entity_id(&credential_schema.id.into())
        .await;
    assert!(
        history
            .values
            .iter()
            .any(|h| h.action == HistoryAction::Updated)
    );
}

#[tokio::test]
async fn test_update_credential_schema_add_format() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({
                "formats": [{ "format": "SD_JWT_VC", "ecosystemSchemaId": "https://vct.example/id" }]
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    let formats = updated.formats.as_ref().await.unwrap();
    assert_eq!(formats.len(), 2);
    let added = formats
        .iter()
        .find(|f| f.format == "SD_JWT_VC".into())
        .unwrap();
    assert_eq!(added.ecosystem_schema_id, "https://vct.example/id");
    let mappings = added.claim_mappings.as_ref().await.unwrap();
    let claim_schemas = updated.claim_schemas.as_ref().await.unwrap();
    for claim_schema in claim_schemas.iter().filter(|c| !c.metadata) {
        let mapping = mappings
            .iter()
            .find(|m| m.claim_schema_id == claim_schema.id)
            .unwrap();
        assert_eq!(mapping.technical_key, claim_schema.key);
        assert_eq!(mapping.namespace, None);
    }
    assert!(claim_schemas.iter().any(|c| c.metadata && c.key == "vct"));
    assert!(mappings.len() > 2);

    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({ "formats": [{ "format": "SD_JWT_VC" }] }),
        )
        .await;
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0439");
}

#[tokio::test]
async fn test_update_credential_schema_clear_optional_fields() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Numeric,
                    length: 4,
                    description: None,
                }),
                expiration: Some(Duration::seconds(3600)),
                ..Default::default()
            },
        )
        .await;
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({ "layoutProperties": { "background": { "color": "#ffffff" } } }),
        )
        .await;
    assert_eq!(resp.status(), 204);

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({ "transactionCode": null, "expiration": null, "layoutProperties": null }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    assert_eq!(updated.transaction_code, None);
    assert_eq!(updated.expiration, None);
    assert_eq!(updated.layout_properties, None);
}

#[tokio::test]
async fn test_update_credential_schema_batch_size_on_non_batch_schema() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(&credential_schema.id, json!({ "batchSize": 3 }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0529");
}

#[tokio::test]
async fn test_update_credential_schema_unknown_claim() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({
                "claims": [{
                    "id": uuid::Uuid::new_v4(),
                    "translations": { "name": { "de": "Vorname" } }
                }]
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0010");
}

#[tokio::test]
async fn test_update_credential_schema_deleted_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                deleted_at: Some(OffsetDateTime::now_utc()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(&credential_schema.id, json!({ "expiration": 60 }))
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_update_credential_schema_merges_nested_objects() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create(
            "test schema",
            &organisation,
            TestingCreateSchemaParams {
                transaction_code: Some(TransactionCode {
                    r#type: TransactionCodeType::Numeric,
                    length: 4,
                    description: Some("code".to_string()),
                }),
                ..Default::default()
            },
        )
        .await;
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({
                "layoutProperties": {
                    "background": { "color": "#ffffff" },
                    "primaryAttribute": "firstName"
                }
            }),
        )
        .await;
    assert_eq!(resp.status(), 204);

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({
                "layoutProperties": {
                    "primaryAttribute": null,
                    "secondaryAttribute": "firstName"
                },
                "transactionCode": { "length": 8 }
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);
    let updated = context
        .db
        .credential_schemas
        .get(&credential_schema.id)
        .await;
    let layout_properties = updated.layout_properties.unwrap();
    assert_eq!(
        layout_properties.background.unwrap().color,
        Some("#ffffff".to_string())
    );
    assert_eq!(layout_properties.primary_attribute, None);
    assert_eq!(
        layout_properties.secondary_attribute,
        Some("firstName".to_string())
    );
    assert_eq!(
        updated.transaction_code,
        Some(TransactionCode {
            r#type: TransactionCodeType::Numeric,
            length: 8,
            description: Some("code".to_string()),
        })
    );
}

#[tokio::test]
async fn test_update_credential_schema_incomplete_transaction_code() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .credential_schemas
        .patch(
            &credential_schema.id,
            json!({ "transactionCode": { "length": 6 } }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0084");
}
