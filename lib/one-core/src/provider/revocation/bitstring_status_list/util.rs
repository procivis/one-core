//! Utilities for Bitstring Status List.

use bitvec::order::Msb0;
use bitvec::view::BitView;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::provider::credential_formatter::model::W3CCredentialStatus;
use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::RevocationState;
use crate::provider::revocation::utils::{gzip_compress, gzip_decompress};

#[derive(Debug, Error)]
pub(crate) enum BitstringError {
    #[error("Bitstring encoding error: `{0}`")]
    Base64Encoding(ct_codecs::Error),
    #[error("Bitstring decoding error: `{0}`")]
    Base64Decoding(ct_codecs::Error),
    #[error("Bitstring compression error: `{0}`")]
    Compression(std::io::Error),
    #[error("Bitstring decompression error: `{0}`")]
    Decompression(std::io::Error),
    #[error("Index `{index}` out of bounds for provided bitstring")]
    IndexOutOfBounds { index: usize },
    #[error("Encoded list has invalid prefix: {0}")]
    InvalidPrefix(String),
}

impl ErrorCodeMixin for BitstringError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0049
    }
}

const MULTIBASE_PREFIX: char = 'u';
const GZIP_PREFIX: &str = "H4s";

pub(crate) fn extract_bitstring_index(
    compressed_list: String,
    index: usize,
) -> Result<bool, BitstringError> {
    let Some(compressed_list) = compressed_list.strip_prefix(MULTIBASE_PREFIX) else {
        return Err(BitstringError::InvalidPrefix(format!(
            "expected multibase prefix: '{MULTIBASE_PREFIX}', input: {compressed_list}"
        )));
    };

    if !compressed_list.starts_with(GZIP_PREFIX) {
        return Err(BitstringError::InvalidPrefix(format!(
            "expected gzip header: {GZIP_PREFIX}, input: {compressed_list}"
        )));
    }

    let compressed = Base64UrlSafeNoPadding::decode_to_vec(compressed_list, None)
        .map_err(BitstringError::Base64Decoding)?;

    let bytes = gzip_decompress(compressed, index).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            BitstringError::IndexOutOfBounds { index }
        } else {
            BitstringError::Decompression(err)
        }
    })?;

    Ok(*bytes
        .view_bits::<Msb0>()
        .get(index)
        .ok_or(BitstringError::IndexOutOfBounds { index })?)
}

pub(super) fn generate_bitstring(
    revoked_indices: Vec<usize>,
    capacity: usize,
) -> Result<String, BitstringError> {
    let mut bytes = vec![0u8; capacity.div_ceil(8)];
    let bits = bytes.view_bits_mut::<Msb0>();
    for index in revoked_indices {
        if index >= capacity {
            return Err(BitstringError::IndexOutOfBounds { index });
        }
        bits.set(index, true);
    }

    let compressed = gzip_compress(bytes).map_err(BitstringError::Compression)?;

    Base64UrlSafeNoPadding::encode_to_string(compressed)
        .map_err(BitstringError::Base64Encoding)
        .map(|s| format!("{MULTIBASE_PREFIX}{s}"))
}

/// Resolve the worst status from W3C statuses
pub(crate) async fn w3c_status_check<'a, F, Fut>(
    status: &'a [W3CCredentialStatus],
    check: F,
) -> Result<RevocationState, RevocationError>
where
    F: Fn(&'a W3CCredentialStatus) -> Fut,
    Fut: std::future::Future<Output = Result<RevocationState, RevocationError>> + Send,
{
    let mut worst_revocation_state = RevocationState::Valid;
    for status_entry in status {
        let status = check(status_entry).await?;
        match status {
            RevocationState::Valid => {}
            RevocationState::Revoked => return Ok(RevocationState::Revoked),
            state @ RevocationState::Suspended { suspend_end_date } => {
                match (worst_revocation_state, suspend_end_date) {
                    (RevocationState::Revoked, _) => {}
                    (RevocationState::Valid, _) => {
                        worst_revocation_state = state;
                    }
                    (RevocationState::Suspended { .. }, None) => {
                        worst_revocation_state = state;
                    }
                    (
                        RevocationState::Suspended {
                            suspend_end_date: None,
                        },
                        _,
                    ) => {}
                    (
                        RevocationState::Suspended {
                            suspend_end_date: Some(previous_suspend_end_date),
                        },
                        Some(new_suspend_end_date),
                    ) => {
                        if previous_suspend_end_date < new_suspend_end_date {
                            worst_revocation_state = state;
                        }
                    }
                }
            }
        }
    }

    Ok(worst_revocation_state)
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    // test vector, no revocations, taken from: https://www.w3.org/TR/vc-status-list/#example-example-statuslist2021credential-0
    const BITSTRING_NO_REVOCATIONS: &str =
        "uH4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";

    // test vector, one revocation on index 1
    const BITSTRING_ONE_REVOCATION: &str =
        "uH4sIAAAAAAAA_-3AsQAAAAACsNDypwqjZ2sAAAAAAAAAAAAAAAAAAACAtwE3F1_NAEAAAA";

    // The test vectors below are generated with a newer version of the compression library producing
    // slightly different bitstrings.

    // test vector, no revocations
    const BITSTRING_NO_REVOCATIONS_NEW: &str =
        "uH4sIAAAAAAAA_-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIDOBobSVKsAQAAA";
    const BITSTRING_ONE_REVOCATION_NEW: &str =
        "uH4sIAAAAAAAA_-3BIQEAAAACIKf5f5UzLEADAAAAAAAAAAAAAAAAAAAA5Gw3F1_NAEAAAA";

    #[test]
    fn test_generate_bitstring() {
        assert_eq!(
            generate_bitstring(vec![], 131072).unwrap(),
            BITSTRING_NO_REVOCATIONS_NEW
        );
        assert_eq!(
            generate_bitstring(vec![1], 131072).unwrap(),
            BITSTRING_ONE_REVOCATION_NEW
        );
    }

    #[test]
    fn test_generate_bitstring_index_out_of_bounds() {
        let result = generate_bitstring(vec![131072], 131072);
        assert!(matches!(
            result,
            Err(BitstringError::IndexOutOfBounds { index: 131072 })
        ));

        // capacity not aligned to bytes - index fits in the padding, but is still out of bounds
        let result = generate_bitstring(vec![10], 10);
        assert!(matches!(
            result,
            Err(BitstringError::IndexOutOfBounds { index: 10 })
        ));
    }

    #[test]
    fn test_extract_bitstring_index_success() {
        assert!(!extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 0).unwrap());
        assert!(extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 1).unwrap());

        assert!(!extract_bitstring_index(BITSTRING_ONE_REVOCATION_NEW.to_owned(), 0).unwrap());
        assert!(extract_bitstring_index(BITSTRING_ONE_REVOCATION_NEW.to_owned(), 1).unwrap());

        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS.to_owned(), 0).unwrap());
        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS.to_owned(), 1).unwrap());

        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS_NEW.to_owned(), 0).unwrap());
        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS_NEW.to_owned(), 1).unwrap());
    }

    #[test]
    fn test_extract_bitstring_invalid_base64() {
        let result = extract_bitstring_index("invalid".to_owned(), 1000000);
        assert!(matches!(result, Err(BitstringError::InvalidPrefix(_))));

        let result = extract_bitstring_index("uH4s3-3?10".to_owned(), 1000000);
        assert!(matches!(result, Err(BitstringError::Base64Decoding(_))));
    }

    #[test]
    fn test_extract_bitstring_index_out_of_bounds() {
        let result = extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 1000000);
        assert!(matches!(
            result,
            Err(BitstringError::IndexOutOfBounds { index: 1000000 })
        ));
    }
}
