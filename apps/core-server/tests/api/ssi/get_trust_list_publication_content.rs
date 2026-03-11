use core_server::endpoint::trust_list_publication::dto::{
    TrustEntryStatusRestEnum, TrustListPublicationRoleRestEnum,
};
use one_core::proto::jwt::Jwt;
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::utils::api_clients::trust_list_publication::CreateTrustListPublicationTestParams;
use crate::utils::context::TestContext;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_list_publication_success() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_trust_list_publication",
            role: TrustListPublicationRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let trust_list_publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    // WHEN
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(trust_list_publication_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/jwt"
    );

    let body = resp.text().await;
    assert!(!body.is_empty());
}

#[tokio::test]
async fn test_get_trust_list_publication_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;
    let non_existent_id = Uuid::new_v4().into();

    // WHEN
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(non_existent_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_get_trust_list_publication_with_entries() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_trust_list_with_entries",
            role: TrustListPublicationRoleRestEnum::PidProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let trust_list_publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    let entry_1_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            trust_list_publication_id,
            identifier.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "Test Entity #1"}]
                }
            })),
        )
        .await;
    assert_eq!(entry_1_resp.status(), 201);

    let entry_2_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            trust_list_publication_id,
            identifier.id,
            Some(serde_json::json!({
                "entity": {
                    "name": [{ "lang": "en", "value": "Test Entity #2"}]
                }
            })),
        )
        .await;
    assert_eq!(entry_2_resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(trust_list_publication_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/jwt"
    );

    let body = resp.text().await;
    assert!(!body.is_empty());
    let jwt = Jwt::<serde_json::Value>::decompose_token(&body).unwrap();
    assert_eq!(
        jwt.payload.custom["ListAndSchemeInformation"]["LoTESequenceNumber"],
        serde_json::Value::Number(3.into())
    );
    assert_eq!(
        jwt.payload.custom["ListAndSchemeInformation"]["SchemeName"][0]["value"],
        serde_json::Value::String("test_trust_list_with_entries".into())
    );
    assert_eq!(
        jwt.payload.custom["TrustedEntitiesList"][0]["TrustedEntityInformation"]["TEName"][0]["value"],
        serde_json::Value::String("Test Entity #2".into())
    );
    assert_eq!(
        jwt.payload.custom["TrustedEntitiesList"][1]["TrustedEntityInformation"]["TEName"][0]["value"],
        serde_json::Value::String("Test Entity #1".into())
    );
}

#[tokio::test]
async fn test_get_trust_list_publication_with_suspended_entries() {
    // GIVEN
    let (context, organisation, identifier, ..) =
        TestContext::new_with_certificate_identifier(None).await;

    let create_resp = context
        .api
        .trust_list_publication
        .create_trust_list_publication(CreateTrustListPublicationTestParams {
            name: "test_trust_list_with_suspended",
            role: TrustListPublicationRoleRestEnum::WalletProvider,
            r#type: "LOTE_PUBLISHER".into(),
            identifier_id: identifier.id,
            organisation_id: organisation.id,
            key_id: None,
            certificate_id: None,
            params: None,
        })
        .await;
    assert_eq!(create_resp.status(), 201);
    let trust_list_publication_id = create_resp.json_value().await["id"].parse::<Uuid>().into();

    let active_entry_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            trust_list_publication_id,
            identifier.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "Active Test Entity"}]
                }
            })),
        )
        .await;
    assert_eq!(active_entry_resp.status(), 201);

    let suspended_entry_resp = context
        .api
        .trust_list_publication
        .create_trust_entry(
            trust_list_publication_id,
            identifier.id,
            Some(serde_json::json!({
                 "entity": {
                    "name": [{ "lang": "en", "value": "Suspended Test Entity"}]
                }
            })),
        )
        .await;
    assert_eq!(suspended_entry_resp.status(), 201);
    let suspended_entry_id = suspended_entry_resp.json_value().await["id"]
        .parse::<Uuid>()
        .into();

    let update_resp = context
        .api
        .trust_list_publication
        .update_trust_entry(
            trust_list_publication_id,
            suspended_entry_id,
            Some(TrustEntryStatusRestEnum::Suspended),
            None,
        )
        .await;
    assert_eq!(update_resp.status(), 204);

    // WHEN
    let resp = context
        .api
        .ssi
        .get_trust_list_publication_content(trust_list_publication_id)
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/jwt"
    );

    let body = resp.text().await;
    assert!(!body.is_empty());
    let jwt = Jwt::<serde_json::Value>::decompose_token(&body).unwrap();
    assert_eq!(
        jwt.payload.custom["ListAndSchemeInformation"]["LoTESequenceNumber"],
        serde_json::Value::Number(4.into())
    );
    assert_eq!(
        jwt.payload.custom["ListAndSchemeInformation"]["SchemeName"][0]["value"],
        serde_json::Value::String("test_trust_list_with_suspended".into())
    );
    assert_eq!(
        jwt.payload.custom["TrustedEntitiesList"][0]["TrustedEntityInformation"]["TEName"][0]["value"],
        serde_json::Value::String("Suspended Test Entity".into())
    );
    assert_eq!(
        jwt.payload.custom["TrustedEntitiesList"][1]["TrustedEntityInformation"]["TEName"][0]["value"],
        serde_json::Value::String("Active Test Entity".into())
    );
}
