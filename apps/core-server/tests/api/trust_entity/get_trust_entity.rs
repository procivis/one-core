use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use similar_asserts::assert_eq;
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
MIIBjTCCAT+gAwIBAgIUc1pDQsDd8ksh6HYWDs14o/5AdVwwBQYDK2VwMCExHzAd
BgNVBAMMFiouZGV2LnByb2NpdmlzLW9uZS5jb20wHhcNMjMwODE2MTYwOTUxWhcN
MzUwMjE0MTYwOTUxWjAhMR8wHQYDVQQDDBYqLmRldi5wcm9jaXZpcy1vbmUuY29t
MCowBQYDK2VwAyEASgRJyZPui8lPLXDEmCMPJr6NOhNluCVU0mUT9SWr71+jgYgw
gYUwHwYDVR0jBBgwFoAUYSDrfq7B9LW8JqFf8Goypix19fswIQYDVR0RBBowGIIW
Ki5kZXYucHJvY2l2aXMtb25lLmNvbTAPBgNVHQ8BAf8EBQMDBwYAMB0GA1UdDgQW
BBRhIOt+rsH0tbwmoV/wajKmLHX1+zAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANB
AOQMEUipnD5WaMEfgd7HwW3sNf9ksH7velfQTrXvTOz86JJgWHcgyOHT8Mq/c2j/
4/iRErr7nVno0osnVOpwfA4=
-----END CERTIFICATE-----";

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
    body["ca"]["commonName"].assert_eq(&"*.dev.procivis-one.com".to_owned());
    body["ca"]["publicKey"]
        .assert_eq(&"4a0449c993ee8bc94f2d70c498230f26be8d3a1365b82554d26513f525abef5f".to_owned());
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
