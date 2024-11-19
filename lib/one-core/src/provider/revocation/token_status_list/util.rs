//! Utilities for Token Status List.

use bit_vec::BitVec;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use thiserror::Error;

use crate::provider::revocation::model::CredentialRevocationState;
use crate::provider::revocation::utils::{gzip_compress, gzip_decompress};

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("Token encoding error: `{0}`")]
    Base64Encoding(ct_codecs::Error),
    #[error("Token decoding error: `{0}`")]
    Base64Decoding(ct_codecs::Error),
    #[error("Token compression error: `{0}`")]
    Compression(std::io::Error),
    #[error("Token decompression error: `{0}`")]
    Decompression(std::io::Error),
    #[error("Index `{index}` out of bounds for provided token")]
    IndexOutOfBounds { index: usize },
    #[error("Encoded list has invalid prefix: {0}")]
    InvalidPrefix(String),
}

// TODO: support different byte sizes (can be 1,2,4,8, specified by "bits" field in JWT statusList.bits field)
pub(crate) const SINGLE_ENTRY_SIZE: usize = 2;
const MULTIBASE_PREFIX: char = 'u';
const GZIP_PREFIX: &str = "H4s";

pub fn extract_token_index(
    compressed_list: String,
    index: usize,
) -> Result<CredentialRevocationState, TokenError> {
    // For backwards compatibility, we allow the compressed list to be passed without the 'u' multibase prefix.
    // see ONE-3528
    let compressed_list = compressed_list
        .strip_prefix(MULTIBASE_PREFIX)
        .unwrap_or(&compressed_list);

    if !compressed_list.starts_with(GZIP_PREFIX) {
        return Err(TokenError::InvalidPrefix(format!(
            "expected gzip header: {GZIP_PREFIX}, input: {}",
            compressed_list
        )));
    }

    let compressed = Base64UrlSafeNoPadding::decode_to_vec(compressed_list, None)
        .map_err(TokenError::Base64Decoding)?;

    let bytes = gzip_decompress(compressed, index * SINGLE_ENTRY_SIZE).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            TokenError::IndexOutOfBounds { index }
        } else {
            TokenError::Decompression(err)
        }
    })?;

    let bits = BitVec::from_bytes(&bytes);

    let bit_index = index * SINGLE_ENTRY_SIZE;
    let suspended = bits
        .get(bit_index)
        .ok_or(TokenError::IndexOutOfBounds { index })?;
    let revoked = bits
        .get(bit_index + 1)
        .ok_or(TokenError::IndexOutOfBounds { index })?;

    match (revoked, suspended) {
        (true, _) => Ok(CredentialRevocationState::Revoked),
        (false, true) => Ok(CredentialRevocationState::Suspended {
            suspend_end_date: None,
        }),
        (_, _) => Ok(CredentialRevocationState::Valid),
    }
}

pub(super) fn generate_token(input: Vec<CredentialRevocationState>) -> Result<String, TokenError> {
    let size = calculate_token_size(input.len());
    let mut bits = BitVec::from_elem(size, false);
    input.into_iter().enumerate().for_each(|(index, state)| {
        let bit_index = index * SINGLE_ENTRY_SIZE;
        match state {
            CredentialRevocationState::Valid => {}
            CredentialRevocationState::Revoked => bits.set(bit_index + 1, true),
            CredentialRevocationState::Suspended { .. } => bits.set(bit_index, true),
        }
    });

    let bytes = bits.to_bytes();
    let compressed = gzip_compress(bytes).map_err(TokenError::Compression)?;

    Base64UrlSafeNoPadding::encode_to_string(compressed)
        .map_err(TokenError::Base64Encoding)
        .map(|s| format!("{MULTIBASE_PREFIX}{}", s))
}

fn calculate_token_size(input_size: usize) -> usize {
    const MINIMUM_INPUT_SIZE: usize = 131072;
    std::cmp::max(
        input_size * SINGLE_ENTRY_SIZE,
        MINIMUM_INPUT_SIZE * SINGLE_ENTRY_SIZE,
    )
}
