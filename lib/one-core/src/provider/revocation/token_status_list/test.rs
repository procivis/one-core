use std::sync::Arc;

use rcgen::{CertificateParams, KeyPair, KeyUsagePurpose};
use rstest::rstest;
use similar_asserts::assert_eq;
use uuid::Uuid;

use super::format_status_list_credential;
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::identifier::IdentifierData;
use crate::model::revocation_list::{RevocationListEntryState, RevocationListPurpose};
use crate::provider::credential_formatter::MockCredentialFormatter;
use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListSubject;
use crate::provider::credential_formatter::model::MockSignatureProvider;
use crate::provider::key_algorithm::provider::{KeyAlgorithmProvider, MockKeyAlgorithmProvider};
use crate::provider::key_storage::provider::MockKeyProvider;
use crate::provider::revocation::token_status_list::util::{
    TokenError, extract_state_from_token, generate_token, get_most_significant_bit_index,
};
use crate::service::test_utilities::{
    dummy_certificate, dummy_identifier, dummy_key, get_dummy_date,
};

#[rstest]
#[tokio::test]
async fn test_format_status_list_with_deleted_issuer_certificate(
    #[values(
        CertificateState::Active,
        CertificateState::Expired,
        CertificateState::Revoked
    )]
    state: CertificateState,
) {
    let mut identifier = dummy_identifier();
    let key = dummy_key();
    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    let certificate = Certificate {
        chain: params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .pem(),
        deleted_at: Some(get_dummy_date()),
        state,
        key: Some(key.clone().into()),
        ..dummy_certificate(identifier.id)
    };
    // A replacement must not take over signing lists tied to the removed certificate.
    let replacement = Certificate {
        chain: certificate.chain.clone(),
        key: Some(dummy_key().into()),
        ..dummy_certificate(identifier.id)
    };
    identifier.data = IdentifierData::Certificate(vec![replacement, certificate.clone()].into());

    let mut key_provider = MockKeyProvider::new();
    key_provider
        .expect_get_signature_provider()
        .once()
        .withf(move |selected, _, _| selected.id == key.id)
        .returning(|_, _, _| Ok(Box::new(MockSignatureProvider::new())));
    let mut formatter = MockCredentialFormatter::new();
    let certificate_id = certificate.id;
    formatter
        .expect_format_status_list()
        .once()
        .withf(move |_, selected, _, _, _, _, _| {
            selected
                .certificate()
                .is_some_and(|certificate| certificate.id == certificate_id)
        })
        .returning(|_, _, _, _, _, _, _| Ok(b"status-list".to_vec()));
    let key_algorithm_provider: Arc<dyn KeyAlgorithmProvider> =
        Arc::new(MockKeyAlgorithmProvider::new());

    let result = format_status_list_credential(
        &Uuid::new_v4().into(),
        &identifier,
        Some(&certificate),
        "encoded-list".to_string(),
        &key_provider,
        &key_algorithm_provider,
        &Some("https://example.com".to_string()),
        &formatter,
        RevocationListPurpose::Revocation,
    )
    .await
    .unwrap();

    assert_eq!(result, b"status-list");
}

fn example_token_status_list_subject_with_bit_size_1() -> (
    TokenStatusListSubject,
    Vec<(usize, RevocationListEntryState)>,
) {
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-in-json-format
    (
        TokenStatusListSubject {
            bits: 1,
            value: "eNrbuRgAAhcBXQ".to_string(),
        },
        vec![
            (0, RevocationListEntryState::Revoked),
            (1, RevocationListEntryState::Active),
            (2, RevocationListEntryState::Active),
            (3, RevocationListEntryState::Revoked),
            (4, RevocationListEntryState::Revoked),
            (5, RevocationListEntryState::Revoked),
            (6, RevocationListEntryState::Active),
            (7, RevocationListEntryState::Revoked),
            (8, RevocationListEntryState::Revoked),
            (9, RevocationListEntryState::Revoked),
            (10, RevocationListEntryState::Active),
            (11, RevocationListEntryState::Active),
            (12, RevocationListEntryState::Active),
            (13, RevocationListEntryState::Revoked),
            (14, RevocationListEntryState::Active),
            (15, RevocationListEntryState::Revoked),
        ],
    )
}

fn example_token_status_list_subject_with_bit_size_2() -> (
    TokenStatusListSubject,
    Vec<(usize, RevocationListEntryState)>,
) {
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-in-json-format
    (
        TokenStatusListSubject {
            bits: 2,
            value: "eNpzdGV1AQACJQDQ".to_string(),
        },
        vec![
            (0, RevocationListEntryState::Revoked),
            (1, RevocationListEntryState::Active),
            (2, RevocationListEntryState::Active),
            (3, RevocationListEntryState::Revoked),
            (4, RevocationListEntryState::Revoked),
            (5, RevocationListEntryState::Revoked),
            (6, RevocationListEntryState::Active),
            (7, RevocationListEntryState::Revoked),
            (8, RevocationListEntryState::Revoked),
            (9, RevocationListEntryState::Revoked),
            (10, RevocationListEntryState::Active),
            (11, RevocationListEntryState::Active),
            (12, RevocationListEntryState::Active),
            (13, RevocationListEntryState::Revoked),
            (14, RevocationListEntryState::Active),
            (15, RevocationListEntryState::Revoked),
        ],
    )
}

#[test]
fn test_get_most_significant_bit_index() {
    // Bit_size: 1
    let bit_size: usize = 1;
    assert_eq!(0, get_most_significant_bit_index(7, bit_size));
    assert_eq!(1, get_most_significant_bit_index(6, bit_size));
    assert_eq!(2, get_most_significant_bit_index(5, bit_size));
    assert_eq!(3, get_most_significant_bit_index(4, bit_size));
    assert_eq!(4, get_most_significant_bit_index(3, bit_size));
    assert_eq!(5, get_most_significant_bit_index(2, bit_size));
    assert_eq!(6, get_most_significant_bit_index(1, bit_size));
    assert_eq!(7, get_most_significant_bit_index(0, bit_size));

    assert_eq!(8, get_most_significant_bit_index(15, bit_size));
    assert_eq!(15, get_most_significant_bit_index(8, bit_size));

    // Bit_size: 2
    let bit_size: usize = 2;
    assert_eq!(0, get_most_significant_bit_index(3, bit_size));
    assert_eq!(2, get_most_significant_bit_index(2, bit_size));
    assert_eq!(4, get_most_significant_bit_index(1, bit_size));
    assert_eq!(6, get_most_significant_bit_index(0, bit_size));

    assert_eq!(8, get_most_significant_bit_index(7, bit_size));
    assert_eq!(10, get_most_significant_bit_index(6, bit_size));
    assert_eq!(12, get_most_significant_bit_index(5, bit_size));
    assert_eq!(14, get_most_significant_bit_index(4, bit_size));

    assert_eq!(16, get_most_significant_bit_index(11, bit_size));
    assert_eq!(18, get_most_significant_bit_index(10, bit_size));
    assert_eq!(20, get_most_significant_bit_index(9, bit_size));
    assert_eq!(22, get_most_significant_bit_index(8, bit_size));

    // Bit_size: 4
    let bit_size: usize = 4;
    assert_eq!(0, get_most_significant_bit_index(1, bit_size));
    assert_eq!(4, get_most_significant_bit_index(0, bit_size));

    assert_eq!(8, get_most_significant_bit_index(3, bit_size));
    assert_eq!(12, get_most_significant_bit_index(2, bit_size));

    assert_eq!(16, get_most_significant_bit_index(5, bit_size));
    assert_eq!(20, get_most_significant_bit_index(4, bit_size));

    // Bit size: 8
    let bit_size: usize = 8;
    assert_eq!(0, get_most_significant_bit_index(0, bit_size));
    assert_eq!(8, get_most_significant_bit_index(1, bit_size));
    assert_eq!(16, get_most_significant_bit_index(2, bit_size));
}

#[test]
fn test_parse_token_status_list() {
    let (subject, states) = example_token_status_list_subject_with_bit_size_1();

    states.into_iter().for_each(|(index, expected)| {
        assert_eq!(
            expected,
            RevocationListEntryState::from(extract_state_from_token(&subject, index).unwrap())
        );
    });
}

#[test]
fn test_generate_token_status_list() {
    const PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_1: usize = 16;
    const PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2: usize = 16 * 2;

    let (example, states) = example_token_status_list_subject_with_bit_size_1();
    let token = generate_token(states, example.bits, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_1).unwrap();
    assert_eq!(example.value, token);

    let (example, states) = example_token_status_list_subject_with_bit_size_2();
    let token = generate_token(states, example.bits, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2).unwrap();
    assert_eq!(example.value, token);

    let state = vec![(0, RevocationListEntryState::Suspended)];
    assert!(matches!(
        generate_token(state, 1, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_1),
        Err(TokenError::SuspensionRequiresAtLeastTwoBits)
    ));
}

#[test]
fn test_generate_and_parse_token_status_list() {
    const PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2: usize = 16 * 2;

    let (_, mut states) = example_token_status_list_subject_with_bit_size_2();
    states[12] = (12, RevocationListEntryState::Suspended);

    let token = generate_token(states.clone(), 2, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2).unwrap();

    let status_list_subject = TokenStatusListSubject {
        value: token,
        bits: 2,
    };

    states.into_iter().for_each(|(index, expected)| {
        assert_eq!(
            expected,
            RevocationListEntryState::from(
                extract_state_from_token(&status_list_subject, index).unwrap()
            )
        );
    });
}

fn example_token_from_spec_with_bits_2() -> (
    TokenStatusListSubject,
    Vec<(usize, RevocationListEntryState)>,
) {
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-token-with-2-bi
    (
        TokenStatusListSubject {
            value: "eNo76fITAAPfAgc".to_string(),
            bits: 2,
        },
        vec![
            (0, RevocationListEntryState::Revoked),
            (1, RevocationListEntryState::Suspended),
            (2, RevocationListEntryState::Active),
            (3, RevocationListEntryState::Revoked),
            (4, RevocationListEntryState::Active),
            (5, RevocationListEntryState::Revoked),
            (6, RevocationListEntryState::Active),
            (7, RevocationListEntryState::Revoked),
            (8, RevocationListEntryState::Revoked),
            (9, RevocationListEntryState::Suspended),
            (10, RevocationListEntryState::Revoked),
            (11, RevocationListEntryState::Revoked),
        ],
    )
}

#[test]
fn test_generate_and_parse_token_from_spec() {
    let (subject, states) = example_token_from_spec_with_bits_2();

    states.iter().for_each(|(index, expected)| {
        assert_eq!(
            *expected,
            RevocationListEntryState::from(extract_state_from_token(&subject, *index).unwrap())
        );
    });

    let token = generate_token(states.clone(), 2usize, 24).unwrap();
    let token_subject = TokenStatusListSubject {
        bits: subject.bits,
        value: token,
    };

    states.into_iter().for_each(|(index, expected)| {
        assert_eq!(
            expected,
            RevocationListEntryState::from(
                extract_state_from_token(&token_subject, index).unwrap()
            )
        );
    });
}
