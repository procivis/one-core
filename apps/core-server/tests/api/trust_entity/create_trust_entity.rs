use core_server::endpoint::ssi::dto::{
    PatchTrustEntityActionRestDTO, PatchTrustEntityRequestRestDTO,
};
use core_server::endpoint::trust_entity::dto::{TrustEntityRoleRest, TrustEntityTypeRest};
use ct_codecs::{Base64, Encoder};
use one_core::model::trust_anchor::TrustAnchor;
use rcgen::{BasicConstraints, CertificateParams, IsCa};
use serde_json::json;
use similar_asserts::assert_eq;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::certificate::{
    create_ca_cert, create_cert, create_intermediate_ca_cert, ecdsa, eddsa,
};
use crate::utils::context::TestContext;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;

#[tokio::test]
async fn test_create_default_trust_entity() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_did_trust_entity() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            Some(TrustEntityTypeRest::Did),
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_identifier_trust_entity() {
    // GIVEN
    let (context, organisation, _, identifier, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_identifier(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            Some(TrustEntityTypeRest::Did),
            &identifier,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_create_ca_trust_entity() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

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

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_ca(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            Some(TrustEntityTypeRest::CertificateAuthority),
            pem_certificate,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 201);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_unknown_trust_id() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let ta = TrustAnchor {
        id: Uuid::new_v4().into(),
        created_date: get_dummy_date(),
        last_modified: get_dummy_date(),
        name: "name".to_owned(),
        publisher_reference: "test".to_string(),
        r#type: "test".to_owned(),
        is_publisher: true,
    };

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &ta,
            None,
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0115", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_trust_role_is_not_publish() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            is_publisher: false,
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0123", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_with_identifier_missing_type() {
    // GIVEN
    let (context, organisation, _, identifier, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_identifier(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &identifier,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0229", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_create_trust_entity_with_ca_missing_type() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let pem_certificate = "-----BEGIN CERTIFICATE-----
MIHkMIGXoAMCAQICFGplpJ84r+DSD8MnjFLdyhcQiGc8MAUGAytlcDAAMCAXDTI1
MDYxNjE1MDQxMloYDzQ3NjMwNTEzMTUwNDEyWjAAMCowBQYDK2VwAyEADPgdSzff
JD51EE4P8hvRxcwsuVAbfbn/6XozFbn4GT+jITAfMB0GA1UdDgQWBBRsnYgGqNo/
0Yrapt79gdzc258hbTAFBgMrZXADQQAGooxtr6luOPyLyhJLDTZMz75hzhbokc4Q
X2qJiGDrkN4Lr/85kRw7KHlsHq/w1aXLp0/Eg/c5aMur6qSWBjMD
-----END CERTIFICATE-----
";

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_ca(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            pem_certificate,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0229", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_to_create_trust_entity_both_identifier_and_did_specified() {
    // GIVEN
    let (context, organisation, did, identifier, _) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create(json!({
            "name": "name",
            "role": TrustEntityRoleRest::Both,
            "trustAnchorId": anchor.id,
            "type": Some(TrustEntityTypeRest::Did),
            "didId": did.id,
            "identifierId": identifier.id,
            "organisationId": organisation.id,
        }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0228", resp.error_code().await);
}

#[tokio::test]
async fn test_delete_trust_entity_fails_if_entity_not_found() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .update(
            Uuid::new_v4().into(),
            PatchTrustEntityRequestRestDTO {
                action: Some(PatchTrustEntityActionRestDTO::Remove),
                ..Default::default()
            },
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
    assert_eq!("BR_0121", resp.error_code().await);
}

#[tokio::test]
async fn test_create_trust_entity_fails_did_already_used() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &did,
            organisation.id,
        )
        .await;
    assert_eq!(resp.status(), 201);

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name2",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn test_fail_create_remote_trust_entity_logo_too_big() {
    // GIVEN
    let (context, _, did, ..) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_remote(
            "name",
            TrustEntityRoleRest::Both,
            None,
            &did,
            Some(format!(
                "data:image/png;base64,{}",
                Base64::encode_to_string([0; 60_000]).unwrap()
            )),
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0193")
}

#[tokio::test]
async fn test_fail_create_trust_entity_organisation_is_deactivated() {
    // GIVEN
    let (context, organisation, did, ..) = TestContext::new_with_did(None).await;
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    context.db.organisations.deactivate(&organisation.id).await;

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create_did(
            "name",
            TrustEntityRoleRest::Both,
            &anchor,
            None,
            &did,
            organisation.id,
        )
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0241", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_trust_entity_root_is_not_ca() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    // Create a self-signed non-CA certificate as the "root"
    let root_ca = create_ca_cert(CertificateParams::default(), eddsa::key());

    let non_ca_root = create_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &root_ca,
        eddsa::key(),
    );

    let leaf_cert = create_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &non_ca_root,
        eddsa::key(),
    );

    let pem_chain = format!("{}{}", leaf_cert.pem(), non_ca_root.pem());

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create(json!({
            "name": "test entity",
            "role": TrustEntityRoleRest::Both,
            "trustAnchorId": anchor.id,
            "type": TrustEntityTypeRest::CertificateAuthority,
            "content": pem_chain,
            "organisationId": organisation.id,
        }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0244", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_trust_entity_root_is_intermediate_ca() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let root_ca = create_ca_cert(CertificateParams::default(), eddsa::key());
    let intermediate_ca = create_intermediate_ca_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &root_ca,
        eddsa::key(),
    );

    let leaf_cert = create_cert(
        CertificateParams::default(),
        eddsa::key(),
        &intermediate_ca,
        ecdsa::key(),
    );

    let pem_chain = format!("{}{}", leaf_cert.pem(), intermediate_ca.pem());

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create(json!({
            "name": "test entity",
            "role": TrustEntityRoleRest::Both,
            "trustAnchorId": anchor.id,
            "type": TrustEntityTypeRest::CertificateAuthority,
            "content": pem_chain,
            "organisationId": organisation.id,
        }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0244", resp.error_code().await);
}

#[tokio::test]
async fn test_fail_create_trust_entity_path_constraint_violation() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams::default())
        .await;

    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    let root_ca = create_ca_cert(params, eddsa::key());

    let intermediate_ca = create_intermediate_ca_cert(
        CertificateParams::default(),
        ecdsa::key(),
        &root_ca,
        eddsa::key(),
    );

    let leaf_cert = create_cert(
        CertificateParams::default(),
        eddsa::key(),
        &intermediate_ca,
        ecdsa::key(),
    );

    // Create a chain: leaf -> intermediate -> root (violates path constraint)
    let pem_chain = format!(
        "{}{}{}",
        leaf_cert.pem(),
        intermediate_ca.pem(),
        root_ca.pem()
    );

    // WHEN
    let resp = context
        .api
        .trust_entities
        .create(json!({
            "name": "test entity with path constraint violation",
            "role": TrustEntityRoleRest::Both,
            "trustAnchorId": anchor.id,
            "type": TrustEntityTypeRest::CertificateAuthority,
            "content": pem_chain,
            "organisationId": organisation.id,
        }))
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!("BR_0250", resp.error_code().await);
}
