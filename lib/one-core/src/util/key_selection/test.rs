use rstest::rstest;
use similar_asserts::assert_eq;

use super::{CertificateFilter, KeySelection, KeySelectionError};
use crate::model::certificate::Certificate;
use crate::model::identifier::{Identifier, IdentifierData};
use crate::service::test_utilities::{
    dummy_certificate, dummy_identifier, dummy_key, get_dummy_date,
};

fn certificate_identifier(is_ca: bool) -> (Identifier, Certificate, Certificate) {
    let mut identifier = dummy_identifier();
    let deleted = Certificate {
        deleted_at: Some(get_dummy_date()),
        key: Some(dummy_key().into()),
        ..dummy_certificate(identifier.id)
    };
    let available = Certificate {
        key: Some(dummy_key().into()),
        ..dummy_certificate(identifier.id)
    };
    let certificates = vec![deleted.clone(), available.clone()].into();
    identifier.data = if is_ca {
        IdentifierData::CertificateAuthority(certificates)
    } else {
        IdentifierData::Certificate(certificates)
    };
    (identifier, deleted, available)
}

#[rstest]
#[tokio::test]
async fn select_key_skips_deleted_certificates(
    #[values(false, true)] is_ca: bool,
    #[values(false, true)] explicit_id: bool,
) {
    let (identifier, _, available) = certificate_identifier(is_ca);

    let selected = identifier
        .select_key(KeySelection {
            certificate: CertificateFilter::id(explicit_id.then_some(available.id)),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(selected.certificate().unwrap().id, available.id);
    assert_eq!(selected.key().id, available.key.unwrap().id());
}

#[rstest]
#[tokio::test]
async fn select_key_rejects_deleted_certificates(
    #[values(false, true)] is_ca: bool,
    #[values(false, true)] explicit_id: bool,
    #[values(false, true)] allow_all_states: bool,
) {
    let (mut identifier, deleted, _) = certificate_identifier(is_ca);
    if !explicit_id {
        // With no explicit ID, the removed certificate is the only candidate.
        match &mut identifier.data {
            IdentifierData::Certificate(certificates)
            | IdentifierData::CertificateAuthority(certificates) => {
                *certificates = vec![deleted.clone()].into();
            }
            _ => unreachable!(),
        }
    }
    let mut certificate_filter = CertificateFilter::id(explicit_id.then_some(deleted.id));
    if allow_all_states {
        certificate_filter = certificate_filter.allow_all_states();
    }

    let result = identifier
        .select_key(KeySelection {
            certificate: certificate_filter,
            ..Default::default()
        })
        .await;

    assert!(matches!(
        result,
        Err(KeySelectionError::NoMatchingCertificate { identifier_id, .. })
            if identifier_id == identifier.id
    ));
}

#[rstest]
#[tokio::test]
async fn list_keys_excludes_deleted_certificates(#[values(false, true)] is_ca: bool) {
    let (identifier, deleted, available) = certificate_identifier(is_ca);

    let keys = identifier.list_keys(None, None).await.unwrap();

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].certificate().unwrap().id, available.id);

    let result = identifier
        .list_keys(None, Some(CertificateFilter::id(Some(deleted.id))))
        .await;

    assert!(matches!(
        result,
        Err(KeySelectionError::NoMatchingCertificate { identifier_id, .. })
            if identifier_id == identifier.id
    ));
}
