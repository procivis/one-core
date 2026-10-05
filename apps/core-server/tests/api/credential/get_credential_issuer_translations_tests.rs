use one_core::model::credential::{CredentialRole, CredentialStateEnum};
use serde_json::json;
use shared_types::{IdentifierId, KeyId};
use similar_asserts::assert_eq;

use crate::fixtures::TestingCredentialParams;
use crate::utils::context::TestContext;
use crate::utils::db_clients::keys::eddsa_testing_params;

const SMALL_PNG_DATA_URI: &str = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

async fn issuer_identifier_with_translations(
    context: &TestContext,
    organisation_id: shared_types::OrganisationId,
    key_id: KeyId,
) -> IdentifierId {
    let resp = context
        .api
        .identifiers
        .create_key_identifier_with_options(
            "issuer-with-translations",
            key_id,
            organisation_id,
            Some(SMALL_PNG_DATA_URI),
            Some(json!({
                "name": { "en": "English issuer", "de": "Deutscher Aussteller" },
                "logoAltText": { "de": "Logo Beschreibung" }
            })),
        )
        .await;
    assert_eq!(resp.status(), 201);
    resp.json_value().await["id"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn test_get_credential_holder_role_returns_issuer_translations_and_logo() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    let issuer_id = issuer_identifier_with_translations(&context, organisation.id, key_id).await;
    let issuer = context.db.identifiers.get(issuer_id).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Holder),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.common.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    let issuer_body = &body["issuer"];
    assert_eq!(issuer_body["translations"]["name"]["en"], "English issuer");
    assert_eq!(
        issuer_body["translations"]["name"]["de"],
        "Deutscher Aussteller"
    );
    assert_eq!(
        issuer_body["translations"]["logoAltText"]["de"],
        "Logo Beschreibung"
    );
    assert_eq!(issuer_body["logo"], SMALL_PNG_DATA_URI);
}

#[tokio::test]
async fn test_get_credential_issuer_role_omits_issuer_translations_and_logo() {
    // GIVEN
    let (context, organisation, ..) = TestContext::new_with_organisation(None).await;
    let key_id = context
        .db
        .keys
        .create(&organisation, eddsa_testing_params())
        .await
        .id;
    let issuer_id = issuer_identifier_with_translations(&context, organisation.id, key_id).await;
    let issuer = context.db.identifiers.get(issuer_id).await;

    let credential_schema = context
        .db
        .credential_schemas
        .create("test", &organisation, Default::default())
        .await;
    let credential = context
        .db
        .credentials
        .create(
            &credential_schema,
            CredentialStateEnum::Accepted,
            &issuer,
            "OPENID4VCI_FINAL1",
            TestingCredentialParams {
                role: Some(CredentialRole::Issuer),
                ..Default::default()
            },
        )
        .await;

    // WHEN
    let resp = context.api.credentials.get(&credential.common.id).await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert!(body["issuer"]["translations"].is_null());
    assert!(body["issuer"]["logo"].is_null());
}
