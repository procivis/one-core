use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use uuid::Uuid;

use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_get_trust_anchor() {
    // GIVEN
    let (context, org, did, ..) = TestContext::new_with_did(None).await;
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    // WHEN
    let resp = context.api.trust_entities.get(entity.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;

    body["id"].assert_eq(&entity.id);
    body["organisationId"].assert_eq(&org.id);
    body["name"].assert_eq(&entity.name);
    body["logo"].assert_eq(&entity.logo);
    body["website"].assert_eq(&entity.website);
    body["termsUrl"].assert_eq(&entity.terms_url);
    body["privacyUrl"].assert_eq(&entity.privacy_url);
    body["role"].assert_eq(&"ISSUER".to_owned());
    body["type"].assert_eq(&"DID".to_owned());
    body["trustAnchor"]["id"].assert_eq(&anchor.id);
    body["did"]["id"].assert_eq(&did.id);
}

#[tokio::test]
async fn test_get_trust_entity_ca() {
    // GIVEN
    let (context, org) = TestContext::new_with_organisation(None).await;
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let pem_certificate = "-----BEGIN CERTIFICATE-----
MIIBJjCB2aADAgECAhRzWkNCwN3ySyHodhYOzXij/kB1XDAFBgMrZXAwITEfMB0G
A1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNvbTAgFw0yNTA2MTcwODUyNTdaGA80
NzYzMDUxNDA4NTI1N1owITEfMB0GA1UEAwwWKi5kZXYucHJvY2l2aXMtb25lLmNv
bTAqMAUGAytlcAMhAAz4HUs33yQ+dRBOD/Ib0cXMLLlQG325/+l6MxW5+Bk/oyEw
HzAdBgNVHQ4EFgQUbJ2IBqjaP9GK2qbe/YHc3NufIW0wBQYDK2VwA0EAsAaCzr02
rpezgIUbslWYL837hwBg08vTFJjBsY0O/D6QTozuYYCSUooMc2izJqcJ9Ga76LS3
JupK8gddPJ2WCw==
-----END CERTIFICATE-----
";

    let trust_entity = context
        .db
        .trust_entities
        .create(
            "trust-entity",
            TrustEntityRole::Both,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::CertificateAuthority,
            "CN=*.dev.procivis-one.com".to_string().into(),
            Some(pem_certificate.to_string()),
            Some(org.clone()),
        )
        .await;

    // WHEN
    let resp = context.api.trust_entities.get(trust_entity.id).await;

    // THEN
    assert_eq!(resp.status(), 200);

    let body = resp.json_value().await;

    body["id"].assert_eq(&trust_entity.id);
    body["organisationId"].assert_eq(&org.id);
    body["name"].assert_eq(&trust_entity.name);
    body["logo"].assert_eq(&trust_entity.logo);
    body["website"].assert_eq(&trust_entity.website);
    body["termsUrl"].assert_eq(&trust_entity.terms_url);
    body["privacyUrl"].assert_eq(&trust_entity.privacy_url);
    body["role"].assert_eq(&"BOTH".to_owned());
    body["trustAnchor"]["id"].assert_eq(&anchor.id);
    body["ca"]["subject"].assert_eq(&"CN=*.dev.procivis-one.com".to_owned());
    body["ca"]["state"].assert_eq(&"ACTIVE".to_owned());
    body["ca"]["serialNumber"]
        .assert_eq(&"73:5a:43:42:c0:dd:f2:4b:21:e8:76:16:0e:cd:78:a3:fe:40:75:5c".to_owned());
    body["content"].assert_eq(&pem_certificate.to_string());
    body["entityKey"].assert_eq(&"CN=*.dev.procivis-one.com".to_string());
    body["type"].assert_eq(&"CA".to_string());
}

#[tokio::test]
async fn test_fail_to_get_trust_entity_unknown_id() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context.api.trust_entities.get(Uuid::new_v4().into()).await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0121", resp.error_code().await);
}
