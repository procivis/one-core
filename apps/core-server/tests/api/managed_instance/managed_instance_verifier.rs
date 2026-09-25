use one_core::model::certificate::{Certificate, CertificateRole, CertificateState};
use one_core::model::identifier::{Identifier, IdentifierType};
use one_core::model::instance::{InstanceRole, InstanceStatus};
use one_core::model::organisation::Organisation;
use one_core::model::revocation_list::{
    RevocationListEntityId, RevocationListEntryState, StatusListCredentialFormat,
};
use rcgen::{CertificateParams, KeyUsagePurpose};
use similar_asserts::assert_eq;
use uuid::Uuid;

use crate::fixtures::TestingIdentifierParams;
use crate::fixtures::certificate::{create_ca_cert, create_cert, ecdsa, eddsa};
use crate::utils::context::TestContext;
use crate::utils::db_clients::certificates::TestingCertificateParams;
use crate::utils::db_clients::keys::ecdsa_testing_params;
use crate::utils::db_clients::managed_instances::TestWalletInstance;
use crate::utils::db_clients::revocation_lists::TestingRevocationListParams;

/// Like `TestContext::new_with_certificate_identifier`, but the leaf certificate is
/// issued with the `cRLSign` key usage required to act as a CRL issuer.
async fn new_with_crl_certificate_identifier(
    context: &TestContext,
    organisation: &Organisation,
) -> (Identifier, Certificate) {
    let key = context
        .db
        .keys
        .create(organisation, ecdsa_testing_params())
        .await;
    let mut ca_params = CertificateParams::default();
    let (ca_cert, ca_issuer) = create_ca_cert(&mut ca_params, eddsa::Key);
    let mut leaf_params = CertificateParams::default();
    leaf_params.key_usages = vec![KeyUsagePurpose::CrlSign];
    let cert = create_cert(&mut leaf_params, ecdsa::Key, &ca_issuer, &ca_params);

    let identifier_id = Uuid::new_v4().into();
    let now = one_core::clock::now_utc();
    let certificate = Certificate {
        id: Uuid::new_v4().into(),
        identifier_id,
        organisation: organisation.clone().into(),
        created_date: now,
        last_modified: now,
        expiry_date: now + time::Duration::minutes(10),
        name: "test cert".to_string(),
        chain: format!("{}{}", cert.pem(), ca_cert.pem()),
        fingerprint: "ffffaaaa".to_string(),
        state: CertificateState::Active,
        roles: vec![
            CertificateRole::Authentication,
            CertificateRole::AssertionMethod,
        ],
        key: Some(key.clone().into()),
        deleted_at: None,
    };

    let identifier = context
        .db
        .identifiers
        .create(
            organisation,
            TestingIdentifierParams {
                r#type: Some(IdentifierType::Certificate),
                certificates: Some(vec![certificate.clone()]),
                ..Default::default()
            },
        )
        .await;

    let certificate = context
        .db
        .certificates
        .create(
            identifier.id,
            organisation.clone(),
            TestingCertificateParams::from(certificate).await,
        )
        .await;
    (identifier, certificate)
}

#[tokio::test]
async fn test_list_managed_instances_returns_all_roles() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                role: Some(InstanceRole::Wallet),
                ..Default::default()
            },
        )
        .await;

    // when: no roles filter
    let resp = context
        .api
        .managed_instances
        .list(crate::utils::api_clients::managed_instances::ListFilters::new(org.id))
        .await;

    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["totalItems"], 2);
}

#[tokio::test]
async fn test_list_managed_instances_honors_explicit_roles_filter() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org.clone(),
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                ..Default::default()
            },
        )
        .await;
    context
        .db
        .managed_instances
        .create(org.clone(), TestWalletInstance::default())
        .await;

    // when: explicitly requesting VERIFIER role
    let resp = context
        .api
        .managed_instances
        .list(crate::utils::api_clients::managed_instances::ListFilters {
            roles: Some(vec!["VERIFIER".to_string()]),
            ..crate::utils::api_clients::managed_instances::ListFilters::new(org.id)
        })
        .await;

    // then: only the verifier instance is returned
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["totalItems"], 1);
    let values = resp["values"].as_array().unwrap();
    assert_eq!(values[0]["id"], verifier_instance.id.to_string());
    assert_eq!(values[0]["role"], "VERIFIER");
}

#[tokio::test]
async fn test_get_managed_instance_verifier_role_success() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                provider: Some("VERIFIER_PROVIDER".to_string()),
                verifier_csr: Some("test-csr".to_string()),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .managed_instances
        .get(&verifier_instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 200);
    let resp = resp.json_value().await;
    assert_eq!(resp["role"], "VERIFIER");
    assert_eq!(resp["providerName"], "VERIFIER_PROVIDER");
    assert_eq!(resp["providerType"], "VERIFIER_PROVIDER");
    assert_eq!(resp["verifierCsr"], "test-csr");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_revoke_managed_instance_verifier_revokes_access_certificates() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    let (identifier, certificate) = new_with_crl_certificate_identifier(&context, &org).await;

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                format: Some(StatusListCredentialFormat::X509Crl),
                r#type: Some("CRL".into()),
                issuer_certificate: Some(certificate),
                ..Default::default()
            }),
        )
        .await;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::Signature("ACCESS_CERTIFICATE".into(), None),
            Some(0),
        )
        .await;

    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                status: Some(InstanceStatus::Active),
                verifier_signature_ids: Some(vec![entry_id]),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .revoke_managed_instance(verifier_instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 204);

    let updated = context
        .db
        .managed_instances
        .get(verifier_instance.id)
        .await
        .unwrap();
    assert_eq!(updated.status, InstanceStatus::Revoked);

    let entries = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].state, RevocationListEntryState::Revoked);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_delete_managed_instance_verifier_revokes_access_certificates() {
    // given
    let (context, org) = TestContext::new_with_organisation(None).await;
    let (identifier, certificate) = new_with_crl_certificate_identifier(&context, &org).await;

    let revocation_list = context
        .db
        .revocation_lists
        .create(
            identifier,
            Some(TestingRevocationListParams {
                format: Some(StatusListCredentialFormat::X509Crl),
                r#type: Some("CRL".into()),
                issuer_certificate: Some(certificate),
                ..Default::default()
            }),
        )
        .await;
    let entry_id = context
        .db
        .revocation_lists
        .create_entry(
            revocation_list.id,
            RevocationListEntityId::Signature("ACCESS_CERTIFICATE".into(), None),
            Some(0),
        )
        .await;

    let verifier_instance = context
        .db
        .managed_instances
        .create(
            org,
            TestWalletInstance {
                role: Some(InstanceRole::Verifier),
                status: Some(InstanceStatus::Pending),
                verifier_signature_ids: Some(vec![entry_id]),
                ..Default::default()
            },
        )
        .await;

    // when
    let resp = context
        .api
        .wallet_provider
        .delete_managed_instance(verifier_instance.id)
        .await;

    // then
    assert_eq!(resp.status(), 204);

    let deleted = context.db.managed_instances.get(verifier_instance.id).await;
    assert_eq!(deleted, None);

    let entries = context
        .db
        .revocation_lists
        .get_entries(revocation_list.id)
        .await;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].state, RevocationListEntryState::Revoked);
}
