use std::collections::HashSet;

use futures::future::join_all;
use one_core::model::blob::BlobType;
use one_core::model::history::{HistoryAction, HistoryEntityType};
use one_core::model::identifier::IdentifierState;
use one_core::model::localized_text::LocalizedTextField;
use one_core::model::organisation::Organisation;
use serde_json::{Value, json};
use shared_types::{DidId, IdentifierId, KeyId, OrganisationId};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::{TestingDidParams, TestingIdentifierParams, TestingKeyParams};
use crate::utils::api_clients::dids::DidKeys;
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

async fn create_key(
    context: &TestContext,
    organisation_id: OrganisationId,
    key_type: &str,
) -> KeyId {
    let response = context
        .api
        .keys
        .create(
            organisation_id,
            key_type,
            &format!("key-{}", Uuid::new_v4()),
        )
        .await;
    assert_eq!(response.status(), 201);
    let body = response.json_value().await;
    Uuid::parse_str(body["id"].as_str().unwrap())
        .unwrap()
        .into()
}

async fn create_did(
    context: &TestContext,
    organisation_id: OrganisationId,
    method: &str,
    keys: DidKeys,
) -> (DidId, IdentifierId) {
    create_did_with_params(context, organisation_id, method, keys, None).await
}

async fn create_did_with_params(
    context: &TestContext,
    organisation_id: OrganisationId,
    method: &str,
    keys: DidKeys,
    params: Option<Value>,
) -> (DidId, IdentifierId) {
    let response = context
        .api
        .dids
        .create(
            organisation_id,
            keys,
            method,
            &format!("did-{}", Uuid::new_v4()),
            params,
        )
        .await;
    assert_eq!(response.status(), 201);
    let body = response.json_value().await;
    let did_id: DidId = Uuid::parse_str(body["id"].as_str().unwrap())
        .unwrap()
        .into();
    let identifier = context.db.identifiers.get_from_did_id(did_id).await;
    (did_id, identifier.id)
}

fn all_roles(key_id: KeyId) -> DidKeys {
    DidKeys {
        assertion_method: vec![key_id],
        authentication: vec![key_id],
        capability_delegation: vec![key_id],
        capability_invocation: vec![key_id],
        key_agreement: vec![key_id],
    }
}

fn all_roles_json(key_id: KeyId) -> Value {
    json!({
        "assertionMethod": [key_id],
        "authentication": [key_id],
        "capabilityDelegation": [key_id],
        "capabilityInvocation": [key_id],
        "keyAgreement": [key_id],
    })
}

fn authentication_and_assertion_json(key_id: KeyId) -> Value {
    json!({
        "assertionMethod": [key_id],
        "authentication": [key_id],
        "capabilityDelegation": [],
        "capabilityInvocation": [],
        "keyAgreement": [],
    })
}

fn key_ids(keys: &Value) -> Vec<String> {
    keys.as_array()
        .unwrap()
        .iter()
        .map(|key| key["id"].as_str().unwrap().to_string())
        .collect()
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

#[tokio::test]
async fn test_update_did_web_keys_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) =
        create_did(&context, organisation.id, "WEB", all_roles(old_key)).await;
    let new_key = create_key(&context, organisation.id, "EDDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier_id, all_roles_json(new_key))
        .await;

    // THEN
    assert_eq!(response.status(), 204);

    let did = context.api.dids.get(&did_id).await.json_value().await;
    for role in [
        "authentication",
        "assertionMethod",
        "keyAgreement",
        "capabilityInvocation",
        "capabilityDelegation",
    ] {
        assert_eq!(key_ids(&did["keys"][role]), vec![new_key.to_string()]);
    }

    let response = context.api.dids.get_did_web_document(&did_id).await;
    assert_eq!(response.status(), 200);
    let document = response.json_value().await;
    let verification_methods = document["verificationMethod"].as_array().unwrap();
    assert_eq!(verification_methods.len(), 1);
    let verification_method_id = verification_methods[0]["id"].as_str().unwrap();
    assert!(verification_method_id.ends_with(&format!("#key-{new_key}")));
    assert!(!document.to_string().contains(&old_key.to_string()));
    assert_eq!(
        document["authentication"][0].as_str().unwrap(),
        verification_method_id
    );
}

#[tokio::test]
async fn test_update_did_webvh_keys_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) = create_did_with_params(
        &context,
        organisation.id,
        "WEBVH",
        DidKeys {
            assertion_method: vec![old_key],
            authentication: vec![old_key],
            capability_delegation: vec![],
            capability_invocation: vec![],
            key_agreement: vec![],
        },
        Some(json!({ "externalHostingUrl": "https://example.com/issuer" })),
    )
    .await;
    let new_key = create_key(&context, organisation.id, "ECDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier_id, authentication_and_assertion_json(new_key))
        .await;

    // THEN
    assert_eq!(response.status(), 204);

    let did = context.api.dids.get(&did_id).await.json_value().await;
    assert_eq!(
        key_ids(&did["keys"]["authentication"]),
        vec![new_key.to_string()]
    );
    assert_eq!(
        key_ids(&did["keys"]["assertionMethod"]),
        vec![new_key.to_string()]
    );

    // the log gained an entry carrying the new document
    let log = context.api.dids.get_did_webvh(&did_id).await.text().await;
    assert_eq!(log.lines().count(), 2);
    assert!(!log.lines().nth(1).unwrap().contains(&old_key.to_string()));
}

#[tokio::test]
async fn test_patch_identifier_applies_did_keys_and_translations_together() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) =
        create_did(&context, organisation.id, "WEB", all_roles(old_key)).await;
    let new_key = create_key(&context, organisation.id, "EDDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .patch(
            &identifier_id,
            json!({
                "did": { "keys": all_roles_json(new_key) },
                "translations": { "name": { "de": "Deutscher Name" } },
            }),
        )
        .await;

    // THEN
    assert_eq!(response.status(), 204);

    let did = context.api.dids.get(&did_id).await.json_value().await;
    assert_eq!(
        key_ids(&did["keys"]["authentication"]),
        vec![new_key.to_string()]
    );

    let texts = context.db.localized_text.get(identifier_id).await;
    assert!(
        texts
            .iter()
            .any(|text| text.lang == "de" && text.value == "Deutscher Name")
    );

    let history = context
        .db
        .histories
        .get_by_entity_id(&identifier_id.into())
        .await;
    assert!(
        history
            .values
            .iter()
            .any(|entry| entry.action == HistoryAction::Updated)
    );
}

#[rstest::rstest]
#[case("KEY")]
#[case("TDW")]
#[tokio::test]
async fn test_update_did_keys_fails_for_unsupported_method(#[case] method: &str) {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) =
        create_did(&context, organisation.id, method, all_roles(old_key)).await;
    let original_did = context.db.dids.get(&did_id).await;
    let new_key = create_key(&context, organisation.id, "ECDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier_id, all_roles_json(new_key))
        .await;

    // THEN
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0181");

    let did = context.db.dids.get(&did_id).await;
    assert_eq!(did.log, original_did.log);
    assert_eq!(did.last_modified, original_did.last_modified);
    assert_eq!(
        &*did.keys.as_ref().await.unwrap(),
        &*original_did.keys.as_ref().await.unwrap()
    );
}

#[tokio::test]
async fn test_update_did_keys_fails_for_deactivated_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let did = context
        .db
        .dids
        .create(
            organisation.clone(),
            TestingDidParams {
                did_method: Some("WEB".into()),
                ..Default::default()
            },
        )
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                did: Some(did),
                state: Some(IdentifierState::Deactivated),
                ..Default::default()
            },
        )
        .await;
    let new_key = create_key(&context, organisation.id, "ECDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier.id, all_roles_json(new_key))
        .await;

    // THEN
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0181");
}

#[tokio::test]
async fn test_update_did_keys_fails_for_non_did_identifier() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = context
        .db
        .keys
        .create(&organisation, ecdsa_testing_params())
        .await;
    let identifier = context
        .db
        .identifiers
        .create(
            &organisation,
            TestingIdentifierParams {
                key: Some(key.clone()),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier.id, all_roles_json(key.id))
        .await;

    // THEN
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0513");
}

#[tokio::test]
async fn test_update_did_web_keys_fails_for_too_many_keys() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (_, identifier_id) = create_did(&context, organisation.id, "WEB", all_roles(old_key)).await;
    let key_1 = create_key(&context, organisation.id, "ECDSA").await;
    let key_2 = create_key(&context, organisation.id, "ECDSA").await;

    // WHEN: did:web allows exactly one keyAgreement key
    let response = context
        .api
        .identifiers
        .update_did_keys(
            &identifier_id,
            json!({
                "assertionMethod": [key_1],
                "authentication": [key_1],
                "capabilityDelegation": [key_1],
                "capabilityInvocation": [key_1],
                "keyAgreement": [key_1, key_2],
            }),
        )
        .await;

    // THEN
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0030");
}

#[tokio::test]
async fn test_update_did_web_keys_fails_for_remote_key() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (_, identifier_id) = create_did(&context, organisation.id, "WEB", all_roles(old_key)).await;
    let remote_key = context
        .db
        .keys
        .create(
            &organisation,
            TestingKeyParams {
                key_reference: None,
                ..ecdsa_testing_params()
            },
        )
        .await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier_id, all_roles_json(remote_key.id))
        .await;

    // THEN
    assert_eq!(response.status(), 400);
    assert_eq!(response.error_code().await, "BR_0076");
}

#[tokio::test]
async fn test_update_did_keys_not_found() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let key = create_key(&context, organisation.id, "ECDSA").await;

    // WHEN
    let response = context
        .api
        .identifiers
        .update_did_keys(&Uuid::new_v4().into(), all_roles_json(key))
        .await;

    // THEN
    assert_eq!(response.status(), 404);
}

#[rstest::rstest]
#[case("WEB", "authentication")]
#[case("WEBVH", "keyAgreement")]
#[tokio::test]
async fn test_update_did_keys_rejects_missing_key_without_changes(
    #[case] method: &str,
    #[case] role: &str,
) {
    let context = TestContext::new_with_core_base_url("https://example.com").await;
    let organisation = context.db.organisations.create().await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) =
        create_did(&context, organisation.id, method, all_roles(old_key)).await;
    let original_did = context.db.dids.get(&did_id).await;
    let original_keys = original_did.keys.as_ref().await.unwrap().to_vec();
    let mut keys = all_roles_json(old_key);
    keys[role] = json!([Uuid::new_v4()]);

    let response = context
        .api
        .identifiers
        .update_did_keys(&identifier_id, keys)
        .await;

    assert_eq!(response.status(), 404);
    assert_eq!(response.error_code().await, "BR_0037");
    let did = context.db.dids.get(&did_id).await;
    assert_eq!(did.log, original_did.log);
    assert_eq!(did.last_modified, original_did.last_modified);
    assert_eq!(&*did.keys.as_ref().await.unwrap(), &original_keys);
}

#[tokio::test]
async fn test_update_did_webvh_keys_concurrently_preserves_log() {
    let context = TestContext::new_with_core_base_url("https://example.com").await;
    let organisation = context.db.organisations.create().await;
    let old_key = create_key(&context, organisation.id, "ECDSA").await;
    let (did_id, identifier_id) =
        create_did(&context, organisation.id, "WEBVH", all_roles(old_key)).await;
    let original_log = context.db.dids.get(&did_id).await.log.unwrap();
    let mut new_keys = Vec::new();
    for _ in 0..8 {
        new_keys.push(create_key(&context, organisation.id, "ECDSA").await);
    }

    let responses = join_all(new_keys.iter().map(|key| {
        context
            .api
            .identifiers
            .update_did_keys(&identifier_id, all_roles_json(*key))
    }))
    .await;
    for response in responses {
        assert_eq!(response.status(), 204, "{}", response.text().await);
    }

    let did = context.db.dids.get(&did_id).await;
    let log = did.log.unwrap();
    assert!(log.starts_with(&original_log));
    let entries: Vec<Value> = log
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(entries.len(), new_keys.len() + 1);
    let expected_references: HashSet<_> = new_keys
        .iter()
        .map(|key| format!("{}#key-{key}", did.did))
        .collect();
    let actual_references: HashSet<_> = entries
        .iter()
        .skip(1)
        .enumerate()
        .map(|(index, entry)| {
            assert!(
                entry["versionId"]
                    .as_str()
                    .unwrap()
                    .starts_with(&format!("{}-", index + 2))
            );
            entry["state"]["authentication"][0]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(actual_references, expected_references);
    let last_reference = entries.last().unwrap()["state"]["authentication"][0]
        .as_str()
        .unwrap();
    let stored_keys = did.keys.as_ref().await.unwrap();
    let authentication_key = stored_keys
        .iter()
        .find(|key| key.role == one_core::model::did::KeyRole::Authentication)
        .unwrap();
    assert_eq!(
        format!("{}#{}", did.did, authentication_key.reference),
        last_reference
    );
}
