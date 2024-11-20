//! Utilities for Token Status List.

use std::io::{Read, Write};

use bit_vec::BitVec;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use thiserror::Error;

use crate::provider::credential_formatter::jwt_formatter::model::TokenStatusListSubject;
use crate::provider::revocation::model::CredentialRevocationState;

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
    #[error("Suspension requires at least two bits")]
    SuspensionRequiresAtLeastTwoBits,
}

pub(crate) const PREFERRED_ENTRY_SIZE: usize = 2;

pub(crate) fn extract_state_from_token(
    status_list: &TokenStatusListSubject,
    index: usize,
) -> Result<CredentialRevocationState, TokenError> {
    let entry_size = status_list.bits;

    let compressed = Base64UrlSafeNoPadding::decode_to_vec(&status_list.value, None)
        .map_err(TokenError::Base64Decoding)?;

    let decoder = ZlibDecoder::new(&compressed[..]);
    let bytes: Vec<u8> = decoder
        .bytes()
        .collect::<Result<_, std::io::Error>>()
        .map_err(|err| {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                TokenError::IndexOutOfBounds { index }
            } else {
                TokenError::Decompression(err)
            }
        })?;

    let bits = BitVec::from_bytes(&bytes);

    let most_significant_bit_index = get_most_significant_bit_index(index, entry_size);

    let suspended = if entry_size > 1 {
        let suspension_bit_index = most_significant_bit_index + entry_size - 2;
        bits.get(suspension_bit_index)
            .ok_or(TokenError::IndexOutOfBounds { index })?
    } else {
        false
    };
    let revocation_bit_index = most_significant_bit_index + entry_size - 1;
    let revoked = bits
        .get(revocation_bit_index)
        .ok_or(TokenError::IndexOutOfBounds { index })?;

    match (revoked, suspended) {
        (true, _) => Ok(CredentialRevocationState::Revoked),
        (false, true) => Ok(CredentialRevocationState::Suspended {
            suspend_end_date: None,
        }),
        (_, _) => Ok(CredentialRevocationState::Valid),
    }
}

pub(super) fn generate_token(
    input: Vec<CredentialRevocationState>,
    bits: usize,
    preferred_token_size: usize,
) -> Result<String, TokenError> {
    let mut bitvec = BitVec::from_elem(preferred_token_size, false);
    input
        .into_iter()
        .enumerate()
        .try_for_each(|(index, state)| {
            let most_significant_bit_index = get_most_significant_bit_index(index, bits);
            match state {
                CredentialRevocationState::Valid => {}
                CredentialRevocationState::Revoked => {
                    let revocation_bit_index = most_significant_bit_index + bits - 1;
                    bitvec.set(revocation_bit_index, true)
                }
                CredentialRevocationState::Suspended { .. } => {
                    if bits < PREFERRED_ENTRY_SIZE {
                        return Err(TokenError::SuspensionRequiresAtLeastTwoBits);
                    }

                    let suspension_bit_index = most_significant_bit_index + bits - 2;
                    bitvec.set(suspension_bit_index, true)
                }
            }

            Ok(())
        })?;

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::best());
    encoder
        .write_all(&bitvec.to_bytes())
        .map_err(TokenError::Compression)?;
    let compressed = encoder.finish().map_err(TokenError::Compression)?;

    Base64UrlSafeNoPadding::encode_to_string(compressed).map_err(TokenError::Base64Encoding)
}

pub(super) fn calculate_preferred_token_size(input_size: usize, bits: usize) -> usize {
    const MINIMUM_INPUT_SIZE: usize = 131072;
    std::cmp::max(input_size * bits, MINIMUM_INPUT_SIZE * bits)
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
