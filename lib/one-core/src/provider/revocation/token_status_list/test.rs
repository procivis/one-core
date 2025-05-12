use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListSubject;
use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::token_status_list::util::{
    TokenError, extract_state_from_token, generate_token, get_most_significant_bit_index,
};

fn example_token_status_list_subject_with_bit_size_1()
-> (TokenStatusListSubject, Vec<CredentialRevocationState>) {
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-in-json-format
    (
        TokenStatusListSubject {
            bits: 1,
            value: "eNrbuRgAAhcBXQ".to_string(),
        },
        vec![
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
        ],
    )
}

fn example_token_status_list_subject_with_bit_size_2()
-> (TokenStatusListSubject, Vec<CredentialRevocationState>) {
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-in-json-format
    (
        TokenStatusListSubject {
            bits: 2,
            value: "eNpzdGV1AQACJQDQ".to_string(),
        },
        vec![
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
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

    states.iter().enumerate().for_each(|(index, expected)| {
        assert_eq!(
            *expected,
            extract_state_from_token(&subject, index).unwrap()
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

    let state = vec![CredentialRevocationState::Suspended {
        suspend_end_date: None,
    }];
    assert!(matches!(
        generate_token(state, 1, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_1),
        Err(TokenError::SuspensionRequiresAtLeastTwoBits)
    ));
}

#[test]
fn test_generate_and_parse_token_status_list() {
    const PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2: usize = 16 * 2;

    let (_, mut states) = example_token_status_list_subject_with_bit_size_2();
    states[12] = CredentialRevocationState::Suspended {
        suspend_end_date: None,
    };

    let token = generate_token(states.clone(), 2, PREFERRED_TOKEN_SIZE_FOR_BIT_SIZE_2).unwrap();

    let status_list_subject = TokenStatusListSubject {
        value: token,
        bits: 2,
    };

    states.iter().enumerate().for_each(|(index, expected)| {
        assert_eq!(
            *expected,
            extract_state_from_token(&status_list_subject, index).unwrap()
        );
    });
}

fn example_token_from_spec_with_bits_2() -> (TokenStatusListSubject, Vec<CredentialRevocationState>)
{
    // Taken from: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#name-status-list-token-with-2-bi
    (
        TokenStatusListSubject {
            value: "eNo76fITAAPfAgc".to_string(),
            bits: 2,
        },
        vec![
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Suspended {
                suspend_end_date: None,
            },
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Valid,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Suspended {
                suspend_end_date: None,
            },
            CredentialRevocationState::Revoked,
            CredentialRevocationState::Revoked,
        ],
    )
}

#[test]
fn test_generate_and_parse_token_from_spec() {
    let (subject, states) = example_token_from_spec_with_bits_2();

    states.iter().enumerate().for_each(|(index, expected)| {
        assert_eq!(
            *expected,
            extract_state_from_token(&subject, index).unwrap()
        );
    });

    let token = generate_token(states.clone(), 2usize, 24).unwrap();
    let token_subject = TokenStatusListSubject {
        bits: subject.bits,
        value: token,
    };

    states.iter().enumerate().for_each(|(index, expected)| {
        assert_eq!(
            *expected,
            extract_state_from_token(&token_subject, index).unwrap()
        );
    });
}
