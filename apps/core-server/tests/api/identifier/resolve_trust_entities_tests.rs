use std::ops::Add;

use one_core::model::certificate::{Certificate, CertificateState};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::organisation::Organisation;
use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState, TrustEntityType};
use rcgen::CertificateParams;
use similar_asserts::assert_eq;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::trust_anchors::TestingTrustAnchorParams;
use crate::utils::field_match::FieldHelpers;

#[tokio::test]
async fn test_identifier_resolve_trust_entity_non_existing_identifier_id() {
    // GIVEN
    let context = TestContext::new(None).await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(Uuid::new_v4().into(), None)])
        .await;

    // THEN
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn test_identifier_resolve_trust_entity_did_with_cert_id_mismatch() {
    // GIVEN
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(identifier.id, Some(Uuid::new_v4().into()))])
        .await;

    // THEN
    assert_eq!(resp.status(), 400);
    assert_eq!(resp.error_code().await, "BR_0242")
}

#[tokio::test]
async fn test_identifier_resolve_trust_entity_did_success() {
    // GIVEN
    let (context, _, did, identifier, _) = TestContext::new_with_did(None).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
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
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(identifier.id, None)])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body[identifier.id.to_string()][0]["entityKey"].assert_eq(&entity.entity_key);
}

#[tokio::test]
async fn test_identifier_resolve_trust_entity_did_unlisted_success() {
    // GIVEN
    let (context, _, _, identifier, _) = TestContext::new_with_did(None).await;
    let trust_anchor_id = Uuid::new_v4();
    context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(identifier.id, None)])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert!(body.as_object().unwrap().is_empty());
}

#[tokio::test]
async fn test_identifier_resolve_trust_entity_certificate_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;
    let (identifier, certificate, ca_cert) =
        prepare_certificate_identifier(&context, &organisation, None).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    let entity = context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::CertificateAuthority,
            eddsa::KEY_IDENTIFIER.to_string().into(),
            Some(ca_cert.pem()),
            identifier.organisation,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(identifier.id, Some(certificate.id))])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body[identifier.id.to_string()][0]["entityKey"].assert_eq(&entity.entity_key);
}

#[tokio::test]
async fn test_identifier_resolve_trust_entity_certificate_expired_unlisted_success() {
    // GIVEN
    let (context, organisation) = TestContext::new_with_organisation(None).await;

    let mut ca_cert_params = CertificateParams::default();
    // Make CA cert expired
    ca_cert_params.not_after = OffsetDateTime::now_utc() - Duration::days(1);
    let (identifier, certificate, ca_cert) =
        prepare_certificate_identifier(&context, &organisation, Some(ca_cert_params)).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    context
        .db
        .trust_entities
        .create(
            "name",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::CertificateAuthority,
            eddsa::KEY_IDENTIFIER.to_string().into(),
            Some(ca_cert.pem()),
            identifier.organisation,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[(identifier.id, Some(certificate.id))])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    assert!(body.as_object().unwrap().is_empty());
}

#[tokio::test]
async fn test_identifier_resolve_did_and_cert_different_anchors_success() {
    // GIVEN
    let (context, organisation, did, did_identifier, _) = TestContext::new_with_did(None).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            name: "did anchor".to_string(),
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    let did_entity = context
        .db
        .trust_entities
        .create(
            "did trust entity",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::Did,
            did.did.into(),
            None,
            did.organisation,
        )
        .await;

    let (cert_identifier, certificate, ca_cert) =
        prepare_certificate_identifier(&context, &organisation, None).await;
    let trust_anchor_id = Uuid::new_v4();
    let anchor = context
        .db
        .trust_anchors
        .create(TestingTrustAnchorParams {
            id: trust_anchor_id,
            name: "cert anchor".to_string(),
            publisher_reference: format!(
                "{}/ssi/trust/v1/{}",
                context.config.app.core_base_url, trust_anchor_id
            ),
            ..Default::default()
        })
        .await;

    let ca_entity = context
        .db
        .trust_entities
        .create(
            "ca trust entity",
            TrustEntityRole::Issuer,
            TrustEntityState::Active,
            anchor.clone(),
            TrustEntityType::CertificateAuthority,
            eddsa::KEY_IDENTIFIER.to_string().into(),
            Some(ca_cert.pem()),
            cert_identifier.organisation,
        )
        .await;

    // WHEN
    let resp = context
        .api
        .identifiers
        .resolve_trust_entities(&[
            (did_identifier.id, None),
            (cert_identifier.id, Some(certificate.id)),
        ])
        .await;

    // THEN
    assert_eq!(resp.status(), 200);
    let body = resp.json_value().await;
    body[did_identifier.id.to_string()][0]["entityKey"].assert_eq(&did_entity.entity_key);
    body[cert_identifier.id.to_string()][0]["entityKey"].assert_eq(&ca_entity.entity_key);
}

async fn prepare_certificate_identifier(
    context: &TestContext,
    organisation: &Organisation,
    ca_cert_params: Option<CertificateParams>,
) -> (Identifier, Certificate, rcgen::Certificate) {
    let key = context
        .db
        .keys
        .create(organisation, ecdsa_testing_params())
        .await;
    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, &eddsa::Key);
    let cert = create_cert(
        &mut ca_cert_params.unwrap_or_default(),
        ecdsa::Key,
        &ca_issuer,
        &ca_params,
    );

    let identifier_id = Uuid::new_v4().into();
    let now = OffsetDateTime::now_utc();
    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation_id: Some(organisation.id),
        created_date: now,
        last_modified: now,
        expiry_date: now.add(Duration::minutes(10)),
        name: "test cert".to_string(),
        chain: format!("{}{}", cert.pem(), ca_cert.pem()),
        fingerprint: "fingerprint".to_string(),
        state: CertificateState::Active,
        key: Some(key.clone()),
    };

    let identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                id: Some(identifier_id),
                r#type: Some(IdentifierType::Certificate),
                certificates: Some(vec![certificate.clone()]),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(identifier.id, TestingCertificateParams::from(certificate))
        .await;
    (identifier, certificate, ca_cert)
}
