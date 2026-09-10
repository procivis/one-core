use serde_json::Value;
use shared_types::{IdentifierId, KeyId};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

const SMALL_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

async fn key_issuer_with_translations(
    context: &TestContext,
    organisation_id: shared_types::OrganisationId,
    key_id: KeyId,
    translations: Option<serde_json::Value>,
    logo: Option<&str>,
) -> IdentifierId {
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "issuer-metadata-translations",
            key_id,
            organisation_id,
            logo,
            translations,
        )
        .await;
    assert_eq!(resp.status(), 201);
    resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

fn display_entries(resp: &Value) -> Vec<Value> {
    let mut entries = resp["display"].as_array().cloned().unwrap();
    entries.sort_by(|a, b| a["locale"].as_str().cmp(&b["locale"].as_str()));
    entries
}

#[tokio::test]
async fn test_issuer_metadata_display_from_identifier_translations_and_logo() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    let identifier_id = key_issuer_with_translations(
        &context,
        organisation.id,
        key_id,
        Some(serde_json::json!({
            "name": { "en": "English issuer", "de": "Deutscher Aussteller" },
            "logoAltText": { "de": "Logo Beschreibung" }
        })),
        Some(SMALL_PNG_DATA_URI),
    )
    .await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier_id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let entries = display_entries(&resp);
    assert_eq!(entries.len(), 2);

    assert_eq!(entries[0]["locale"], "de");
    assert_eq!(entries[0]["name"], "Deutscher Aussteller");
    assert_eq!(entries[0]["logo"]["uri"], SMALL_PNG_DATA_URI);
    assert_eq!(entries[0]["logo"]["alt_text"], "Logo Beschreibung");

    assert_eq!(entries[1]["locale"], "en");
    assert_eq!(entries[1]["name"], "English issuer");
    assert_eq!(entries[1]["logo"]["uri"], SMALL_PNG_DATA_URI);
    assert!(entries[1]["logo"]["alt_text"].is_null());
}

#[tokio::test]
async fn test_issuer_metadata_display_falls_back_to_default_language_without_translations() {
    // GIVEN – identifier created without a `translations` block still gets a
    // default-language `Name` row from the plain identifier name.
    let (context, organisation, ..) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    let identifier_id =
        key_issuer_with_translations(&context, organisation.id, key_id, None, None).await;
    let credential_schema = context
        .db
        .credential_schemas
        .create("test_schema", &organisation, Default::default())
        .await;

    // WHEN
    let resp = context
        .api
        .ssi
        .openid_credential_issuer_final1(
            "OPENID4VCI_FINAL1",
            identifier_id,
            credential_schema.id,
            mime::APPLICATION_JSON.into(),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    let entries = resp["display"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["locale"], "en");
    assert_eq!(entries[0]["name"], "issuer-metadata-translations");
    assert!(entries[0]["logo"].is_null());
}
