//! Coverage for ONE story task 1: `POST /api/identifier/v1` with the optional
//! `logo` and `translations` fields, and the matching read side on
//! `GET /api/identifier/v1{,/{id}}`.
//!
//! Verified requirements:
//! * request accepts `translations { name, logoAltText }` and `logo`
//! * `logo` larger than 200 KB (decoded) is rejected with `BR_0193`
//! * `logo` is stored in blob storage as an `IDENTIFIER_LOGO` blob and
//!   referenced from `identifier.logo`
//! * when no `translations` are provided the mandatory name is still written to
//!   the localized text table using the configured default language (`en`)
//! * provided translations are persisted as localized text rows
//! * `GET /api/identifier/v1/{id}` returns `logo` and a mandatory `translations`
//!   block, falling back to `{ en: <name> }` when the identifier has no
//!   localized text
//! * `GET /api/identifier/v1` only returns `logo` / `translations` for list
//!   items when requested via `include[]`

use ct_codecs::{Base64, Encoder};
use one_core::model::blob::BlobType;
use one_core::model::localized_text::{LocalizedTextEntityType, LocalizedTextField};
use one_core::model::organisation::Organisation;
use serde_json::json;
use shared_types::{EntityId, IdentifierId, KeyId};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

const SMALL_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

async fn setup() -> (TestContext, Organisation, KeyId) {
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    (context, organisation, key_id)
}

#[tokio::test]
async fn test_create_identifier_persists_logo_blob_and_translations() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-with-translations",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            Some(json!({
                "name": { "en": "English name", "de": "Deutscher Name" },
                "logoAltText": { "en": "alt en", "de": "alt de" }
            })),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // logo stored in blob storage and referenced from the identifier
    let identifier = context.db.identifiers.get(identifier_id).await;
    let logo_blob_id = identifier.logo.expect("identifier.logo should be set");
    let blob = context
        .db
        .blobs
        .get(&logo_blob_id)
        .await
        .expect("logo blob should exist");
    assert_eq!(blob.r#type, BlobType::IdentifierLogo);
    assert_eq!(blob.value, SMALL_PNG_DATA_URI.as_bytes());

    // translations persisted as localized text rows
    let texts = context.db.localized_text.get(identifier_id).await;
    assert_eq!(texts.len(), 4);
    for text in &texts {
        assert_eq!(text.entity_type, LocalizedTextEntityType::Identifier);
        assert_eq!(text.entity_id, EntityId::from(identifier_id));
    }
    let lookup = |field: LocalizedTextField, lang: &str| {
        texts
            .iter()
            .find(|t| t.field == field && t.lang == lang)
            .map(|t| t.value.as_str())
    };
    assert_eq!(lookup(LocalizedTextField::Name, "en"), Some("English name"));
    assert_eq!(
        lookup(LocalizedTextField::Name, "de"),
        Some("Deutscher Name")
    );
    assert_eq!(
        lookup(LocalizedTextField::LogoAltText, "en"),
        Some("alt en")
    );
    assert_eq!(
        lookup(LocalizedTextField::LogoAltText, "de"),
        Some("alt de")
    );
}

#[tokio::test]
async fn test_create_identifier_without_translations_writes_default_language_name() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN – neither `translations` nor `logo` provided
    let resp = context
        .api
        .identifiers
        .create_key_identifier("identifier-no-translations", key_id, organisation.id)
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let identifier = context.db.identifiers.get(identifier_id).await;
    assert!(identifier.logo.is_none());

    // exactly one localized text row: the mandatory name in the configured
    // default language (`en`)
    let texts = context.db.localized_text.get(identifier_id).await;
    assert_eq!(texts.len(), 1);
    assert_eq!(texts[0].field, LocalizedTextField::Name);
    assert_eq!(texts[0].lang, "en");
    assert_eq!(texts[0].value, "identifier-no-translations");
    assert_eq!(texts[0].entity_type, LocalizedTextEntityType::Identifier);
}

#[tokio::test]
async fn test_create_identifier_with_logo_but_no_translations() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN – `logo` provided, `translations` omitted
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-logo-only",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let identifier = context.db.identifiers.get(identifier_id).await;
    let logo_blob_id = identifier.logo.expect("identifier.logo should be set");
    let blob = context.db.blobs.get(&logo_blob_id).await.unwrap();
    assert_eq!(blob.r#type, BlobType::IdentifierLogo);

    // still falls back to the mandatory default-language name
    let texts = context.db.localized_text.get(identifier_id).await;
    assert_eq!(texts.len(), 1);
    assert_eq!(texts[0].field, LocalizedTextField::Name);
    assert_eq!(texts[0].lang, "en");
    assert_eq!(texts[0].value, "identifier-logo-only");
}

#[tokio::test]
async fn test_create_identifier_logo_larger_than_200kb_is_rejected() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // 210 KB of decoded payload – above the 200 KB identifier logo limit
    let oversized = Base64::encode_to_string(vec![0u8; 210 * 1024]).unwrap();

    // WHEN
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-oversized-logo",
            key_id,
            organisation.id,
            Some(&format!("data:image/png;base64,{oversized}")),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193");

    // nothing was created
    let list = context.api.identifiers.list(&organisation.id, None).await;
    assert_eq!(list.json_value().await["totalItems"].as_i64().unwrap(), 0);
}

#[tokio::test]
async fn test_create_identifier_logo_with_invalid_format_is_rejected() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN – not a supported `data:image/...;base64,` URI
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-bad-logo",
            key_id,
            organisation.id,
            Some("totally-not-an-image"),
            None,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193");
}

/// Partial translations: the provided languages are persisted as-is, and the
/// mandatory name in the configured default language (`en`) is backfilled from
/// `name` at create time, matching the `backfill_default_translations` behaviour
/// used for credential schemas.
#[tokio::test]
async fn test_create_identifier_with_partial_translations_backfills_default_language_name() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN – only a German name, no English, no logoAltText
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-partial-translations",
            key_id,
            organisation.id,
            None,
            Some(json!({ "name": { "de": "Nur Deutsch" } })),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let texts = context.db.localized_text.get(identifier_id).await;
    let mut name_rows: Vec<_> = texts
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    name_rows.sort_by(|a, b| a.lang.cmp(&b.lang));
    assert_eq!(name_rows.len(), 2);
    assert_eq!(name_rows[0].lang, "de");
    assert_eq!(name_rows[0].value, "Nur Deutsch");
    // backfilled from the identifier `name`
    assert_eq!(name_rows[1].lang, "en");
    assert_eq!(name_rows[1].value, "identifier-partial-translations");
}

/// A `translations` block with an empty `name` map must not drop the mandatory
/// name: it falls back to the identifier name in the configured default
/// language (`en`), same as omitting `translations` entirely.
#[tokio::test]
async fn test_create_identifier_with_empty_translations_name_falls_back_to_default_language() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;

    // WHEN – `translations` present but `name` map is empty, `logoAltText` set
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-empty-name-translations",
            key_id,
            organisation.id,
            None,
            Some(json!({ "name": {}, "logoAltText": { "de": "alt de" } })),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
    let identifier_id: IdentifierId = resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let texts = context.db.localized_text.get(identifier_id).await;
    let name_rows: Vec<_> = texts
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert_eq!(name_rows.len(), 1);
    assert_eq!(name_rows[0].lang, "en");
    assert_eq!(name_rows[0].value, "identifier-empty-name-translations");
    assert_eq!(
        name_rows[0].entity_type,
        LocalizedTextEntityType::Identifier
    );

    // the provided logoAltText entry is still persisted
    let logo_alt_rows: Vec<_> = texts
        .iter()
        .filter(|t| t.field == LocalizedTextField::LogoAltText)
        .collect();
    assert_eq!(logo_alt_rows.len(), 1);
    assert_eq!(logo_alt_rows[0].lang, "de");
    assert_eq!(logo_alt_rows[0].value, "alt de");
}

// ---------------------------------------------------------------------------
// GET side
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_get_identifier_returns_logo_and_translations() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-get-translations",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            Some(json!({
                "name": { "en": "English name", "de": "Deutscher Name" },
                "logoAltText": { "en": "alt en", "de": "alt de" }
            })),
        )
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // WHEN
    let resp = context.api.identifiers.get(&identifier_id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert_eq!(body["logo"].as_str().unwrap(), SMALL_PNG_DATA_URI);
    assert_eq!(body["translations"]["name"]["en"], "English name");
    assert_eq!(body["translations"]["name"]["de"], "Deutscher Name");
    assert_eq!(body["translations"]["logoAltText"]["en"], "alt en");
    assert_eq!(body["translations"]["logoAltText"]["de"], "alt de");
}

#[tokio::test]
async fn test_get_identifier_without_translations_falls_back_to_default_language() {
    // GIVEN – identifier created without `translations` / `logo`
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier("identifier-get-fallback", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // WHEN
    let resp = context.api.identifiers.get(&identifier_id).await;

    // THEN – no 500, mandatory `translations.name` falls back to `{ en: <name> }`
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert!(body["logo"].is_null());
    assert_eq!(
        body["translations"]["name"],
        json!({ "en": "identifier-get-fallback" })
    );
    assert!(body["translations"]["logoAltText"].is_null());
}

#[tokio::test]
async fn test_get_identifier_list_include_translations_and_logo() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-list-include",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            Some(json!({ "name": { "en": "English name" } })),
        )
        .await;

    // WHEN – without include[]
    let plain = context
        .api
        .identifiers
        .list(&organisation.id, None)
        .await
        .json_value()
        .await;

    // THEN – list items carry neither logo nor translations
    assert_eq!(plain["values"][0]["name"], "identifier-list-include");
    assert!(plain["values"][0]["logo"].is_null());
    assert!(plain["values"][0]["translations"].is_null());

    // WHEN – with include[]=translations&include[]=logo
    let included = context
        .api
        .identifiers
        .list(
            &organisation.id,
            Some("include[]=translations&include[]=logo".to_string()),
        )
        .await
        .json_value()
        .await;

    // THEN
    assert_eq!(
        included["values"][0]["logo"].as_str().unwrap(),
        SMALL_PNG_DATA_URI
    );
    assert_eq!(
        included["values"][0]["translations"]["name"]["en"],
        "English name"
    );
}

#[tokio::test]
async fn test_create_identifier_with_trust_information_fails_without_access_certificate() {
    // given: a KEY identifier carries no access certificate the registration certificate could be matched against
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;

    // when
    let result = context
        .api
        .identifiers
        .create_key_identifier_with_trust_information(
            "identifier-with-trust-information",
            key_id,
            organisation.id,
            "not-a-real-registration-certificate-jwt",
        )
        .await;

    // then
    assert_eq!(result.status(), 400);
    assert_eq!(result.error_code().await, "BR_0416");
}

#[tokio::test]
async fn test_delete_identifier_removes_logo_blob() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-delete-logo",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            None,
        )
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let logo_blob_id = context
        .db
        .identifiers
        .get(identifier_id)
        .await
        .logo
        .unwrap();
    assert!(context.db.blobs.get(&logo_blob_id).await.is_some());

    // WHEN
    let resp = context.api.identifiers.delete(&identifier_id).await;

    // THEN
    assert_eq!(resp.status(), 204);
    assert!(context.db.blobs.get(&logo_blob_id).await.is_none());
    assert!(
        context
            .db
            .identifiers
            .get(identifier_id)
            .await
            .logo
            .is_none()
    );
}
