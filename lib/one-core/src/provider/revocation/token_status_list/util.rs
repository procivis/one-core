//! Utilities for Token Status List.

use std::io::{BufReader, Read, Write};

use bitvec::order::Msb0;
use bitvec::view::BitView;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use thiserror::Error;

use crate::error::{ErrorCode, ErrorCodeMixin};
use crate::model::revocation_list::RevocationListEntryState;
use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListSubject;
use crate::provider::revocation::model::RevocationState;

#[derive(Debug, Error)]
pub(super) enum TokenError {
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
    #[error("Suspension requires at least two bits")]
    SuspensionRequiresAtLeastTwoBits,
    #[error("Invalid entry size: {0}")]
    InvalidEntrySize(usize),
}

impl ErrorCodeMixin for TokenError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0101
    }
}

pub(super) fn extract_state_from_token(
    status_list: &TokenStatusListSubject,
    index: usize,
) -> Result<RevocationState, TokenError> {
    let entry_size = status_list.bits;
    if ![1, 2, 4, 8].contains(&entry_size) {
        return Err(TokenError::InvalidEntrySize(entry_size));
    }
    let entry_bit_index = index * entry_size;

    let compressed = Base64UrlSafeNoPadding::decode_to_vec(&status_list.value, Some(&[b'='; 4]))
        .map_err(TokenError::Base64Decoding)?;

    let decoder = ZlibDecoder::new(&compressed[..]);
    let target_byte = BufReader::new(decoder)
        .bytes()
        .nth(entry_bit_index / 8)
        .ok_or(TokenError::IndexOutOfBounds { index })?
        .map_err(TokenError::Decompression)?;
    let bits = target_byte.view_bits::<Msb0>();
    let revocation_bit_index = 7 - (entry_bit_index % 8);

    let revoked = *bits
        .get(revocation_bit_index)
        .ok_or(TokenError::IndexOutOfBounds { index })?;
    if revoked {
        return Ok(RevocationState::Revoked);
    }

    if entry_size > 1 {
        let suspension_bit_index = revocation_bit_index - 1;
        let suspended = *bits
            .get(suspension_bit_index)
            .ok_or(TokenError::IndexOutOfBounds { index })?;
        if suspended {
            return Ok(RevocationState::Suspended {
                suspend_end_date: None,
            });
        }
    }

    Ok(RevocationState::Valid)
}

pub(super) fn generate_token(
    input: Vec<(usize, RevocationListEntryState)>,
    bits: usize,
    capacity: usize,
) -> Result<String, TokenError> {
    let mut bytes = vec![0u8; (capacity * bits).div_ceil(8)];
    let status_bits = bytes.view_bits_mut::<Msb0>();
    input.into_iter().try_for_each(|(index, state)| {
        if index >= capacity {
            return Err(TokenError::IndexOutOfBounds { index });
        }
        let most_significant_bit_index = get_most_significant_bit_index(index, bits);
        match state {
            RevocationListEntryState::Active => {}
            RevocationListEntryState::Revoked => {
                let revocation_bit_index = most_significant_bit_index + bits - 1;
                status_bits.set(revocation_bit_index, true)
            }
            RevocationListEntryState::Suspended => {
                if bits < 2 {
                    return Err(TokenError::SuspensionRequiresAtLeastTwoBits);
                }
                let suspension_bit_index = most_significant_bit_index + bits - 2;
                status_bits.set(suspension_bit_index, true)
            }
        }
        Ok(())
    })?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(&bytes).map_err(TokenError::Compression)?;
    let compressed = encoder.finish().map_err(TokenError::Compression)?;

    Base64UrlSafeNoPadding::encode_to_string(compressed).map_err(TokenError::Base64Encoding)
}

pub(super) fn get_most_significant_bit_index(index: usize, bit_size: usize) -> usize {
    // Take a look here to understand how it works: https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-03.html#section-10.1
    const BYTE_SIZE: usize = 8;

    let words_in_byte = BYTE_SIZE / bit_size;
    let word_size = BYTE_SIZE / words_in_byte;

    let byte_number = (index * word_size) / BYTE_SIZE;
    let byte_start_index = BYTE_SIZE * byte_number;

    let smallest_index_in_byte = byte_number * words_in_byte;
    let word_index_within_byte = index - smallest_index_in_byte;

    byte_start_index + BYTE_SIZE - (word_index_within_byte * word_size) - word_size
}
