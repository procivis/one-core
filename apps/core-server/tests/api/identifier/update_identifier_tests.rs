use one_core::model::blob::BlobType;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::localized_text::LocalizedTextField;
use one_core::model::organisation::Organisation;
use serde_json::json;
use shared_types::{IdentifierId, KeyId};
use similar_asserts::assert_eq;

use crate::utils::context::TestContext;
use crate::utils::db_clients::blobs::TestingBlobParams;
use crate::utils::db_clients::identifier_trust_information::TestingIdentifierTrustInformationParams;
use crate::utils::db_clients::keys::{ecdsa_testing_params, eddsa_testing_params};

const SMALL_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
const OTHER_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYPhfDwAChAGA60e6kgAAAABJRU5ErkJggg==";

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

fn history_contains(
    entries: &one_core::model::history::GetHistoryList<u64>,
    action: HistoryAction,
) -> bool {
    entries
        .values
        .iter()
        .any(|entry| entry.entity_type == HistoryEntityType::Identifier && entry.action == action)
}

#[tokio::test]
async fn test_patch_identifier_swaps_key() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier("identifier-key-swap", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let new_key_id = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await
        .id;

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier_id, json!({ "key": { "keyId": new_key_id } }))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let get_resp = context.api.identifiers.get(&identifier_id).await;
    assert_eq!(get_resp.status(), 200);
    let body = get_resp.json_value().await;
    assert_eq!(body["key"]["id"].as_str().unwrap(), new_key_id.to_string());

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(history_contains(&history, HistoryAction::Updated));
}

#[tokio::test]
async fn test_patch_identifier_key_on_non_key_identifier_fails() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_did_identifier("identifier-did", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    let other_key_id = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await
        .id;

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier_id, json!({ "key": { "keyId": other_key_id } }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0513");
}

#[tokio::test]
async fn test_patch_identifier_logo_and_translations_replace() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-patch-logo-translations",
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

    let old_logo_blob_id = context
        .db
        .identifiers
        .get(identifier_id)
        .await
        .logo
        .unwrap();

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(
            &identifier_id,
            json!({
                "logo": OTHER_PNG_DATA_URI,
                "translations": {
                    "name": { "fr": "Nom francais" }
                }
            }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    // the existing logo blob keeps its id, only its content changes
    let identifier = context.db.identifiers.get(identifier_id).await;
    assert_eq!(identifier.logo, Some(old_logo_blob_id));
    let blob = context.db.blobs.get(&old_logo_blob_id).await.unwrap();
    assert_eq!(blob.r#type, BlobType::IdentifierLogo);
    assert_eq!(blob.value, OTHER_PNG_DATA_URI.as_bytes());

    // translations fully replaced: old languages (de) are gone, fr is present, en is
    // backfilled from the identifier's name (not the previously-provided "English name")
    let texts = context.db.localized_text.get(identifier_id).await;
    let name_rows: Vec<_> = texts
        .iter()
        .filter(|t| t.field == LocalizedTextField::Name)
        .collect();
    assert!(!name_rows.iter().any(|t| t.lang == "de"));
    assert!(
        name_rows
            .iter()
            .any(|t| t.lang == "fr" && t.value == "Nom francais")
    );
    assert!(
        name_rows
            .iter()
            .any(|t| t.lang == "en" && t.value == "identifier-patch-logo-translations")
    );
    // logoAltText rows from the old translations are gone entirely
    assert!(
        !texts
            .iter()
            .any(|t| t.field == LocalizedTextField::LogoAltText)
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(history_contains(&history, HistoryAction::Updated));
}

#[tokio::test]
async fn test_patch_identifier_trust_information_empty_removes_all() {
    // GIVEN
    let (context, _organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let blob = context
        .db
        .blobs
        .create(TestingBlobParams {
            r#type: Some(BlobType::RegistrationCertificate),
            ..Default::default()
        })
        .await;
    context
        .db
        .identifier_trust_information
        .create(
            identifier.id,
            blob.id,
            TestingIdentifierTrustInformationParams::default(),
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier.id, json!({ "trustInformation": [] }))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    // the blob backing the removed trust information row is gone
    assert!(context.db.blobs.get(&blob.id).await.is_none());

    let get_resp = context.api.identifiers.get(&identifier.id).await;
    let body = get_resp.json_value().await;
    assert!(
        body["trustInformation"].is_null()
            || body["trustInformation"].as_array().unwrap().is_empty()
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier.id.into())
        .await;
    assert!(history_contains(&history, HistoryAction::Updated));
}

#[tokio::test]
async fn test_patch_identifier_empty_body_only_bumps_and_writes_history() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier("identifier-empty-patch", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier_id, json!({}))
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(history_contains(&history, HistoryAction::Updated));
}

#[tokio::test]
async fn test_patch_identifier_not_found_for_deleted_identifier() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier("identifier-deleted-patch", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let delete_resp = context.api.identifiers.delete(&identifier_id).await;
    assert_eq!(delete_resp.status(), 204);

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier_id, json!({ "logo": SMALL_PNG_DATA_URI }))
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_patch_identifier_unknown_field_rejected() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier("identifier-unknown-field", key_id, organisation.id)
        .await
        .json_value()
        .await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(&identifier_id, json!({ "notARealField": true }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_patch_identifier_null_logo_and_translations_removes_them() {
    // GIVEN
    let (context, organisation, key_id) = setup().await;
    let identifier_id: IdentifierId = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "identifier-patch-null",
            key_id,
            organisation.id,
            Some(SMALL_PNG_DATA_URI),
            Some(json!({
                "name": { "en": "English name", "de": "Deutscher Name" },
                "logoAltText": { "en": "alt en" }
            })),
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

    // WHEN
    let resp = context
        .api
        .identifiers
        .patch(
            &identifier_id,
            json!({ "logo": null, "translations": null }),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 204);

    let identifier = context.db.identifiers.get(identifier_id).await;
    assert!(identifier.logo.is_none());
    assert!(context.db.blobs.get(&logo_blob_id).await.is_none());

    let texts = context.db.localized_text.get(identifier_id).await;
    assert_eq!(texts.len(), 1);
    assert_eq!(texts[0].field, LocalizedTextField::Name);
    assert_eq!(texts[0].lang, "en");
    assert_eq!(texts[0].value, "identifier-patch-null");

    let body = context
        .api
        .identifiers
        .get(&identifier_id)
        .await
        .json_value()
        .await;
    assert!(body["logo"].is_null());

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(history_contains(&history, HistoryAction::Updated));
}
