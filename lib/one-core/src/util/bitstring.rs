use std::io::{Read, Write};

use bit_vec::BitVec;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use flate2::{bufread::GzDecoder, write::GzEncoder};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BitstringError {
    #[error("Base64 error: `{0}`")]
    Base64Error(ct_codecs::Error),
    #[error("IO error: `{0}`")]
    IoError(std::io::Error),
    #[error("Parsing error: `{0}`")]
    ParsingError(String),
}

fn gzip_compress(input: Vec<u8>) -> Result<Vec<u8>, BitstringError> {
    let mut encoder = GzEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&input).map_err(BitstringError::IoError)?;
    encoder.finish().map_err(BitstringError::IoError)
}

fn gzip_decompress(input: Vec<u8>, up_to_bit_index: usize) -> Result<Vec<u8>, BitstringError> {
    let mut decoder = GzDecoder::new(&input[..]);
    let mut result: Vec<u8> = vec![0; 1 + (up_to_bit_index / 8)];
    decoder
        .read_exact(&mut result)
        .map_err(BitstringError::IoError)?;
    Ok(result)
}

fn calculate_bitstring_size(input_size: usize) -> usize {
    const MINIMUM_INPUT_SIZE: usize = 131072;
    std::cmp::max(input_size, MINIMUM_INPUT_SIZE)
}

pub fn generate_bitstring(input: Vec<bool>) -> Result<String, BitstringError> {
    let size = calculate_bitstring_size(input.len());
    let mut bits = BitVec::from_elem(size, false);
    input.into_iter().enumerate().for_each(|(index, state)| {
        if state {
            bits.set(index, true)
        }
    });

    let bytes = bits.to_bytes();
    let compressed = gzip_compress(bytes)?;
    Base64UrlSafeNoPadding::encode_to_string(compressed).map_err(BitstringError::Base64Error)
}

pub fn extract_bitstring_index(input: String, index: usize) -> Result<bool, BitstringError> {
    let compressed =
        Base64UrlSafeNoPadding::decode_to_vec(input, None).map_err(BitstringError::Base64Error)?;
    let bytes = gzip_decompress(compressed, index)?;
    let bits = BitVec::from_bytes(&bytes);
    bits.get(index)
        .ok_or(BitstringError::ParsingError("index not found".to_string()))
}

#[cfg(test)]
mod test {
    use super::*;

    // test vector, no revocations, taken from: https://www.w3.org/TR/vc-status-list/#example-example-statuslist2021credential-0
    const BITSTRING_NO_REVOCATIONS: &str =
        "H4sIAAAAAAAAA-3BMQEAAADCoPVPbQwfoAAAAAAAAAAAAAAAAAAAAIC3AYbSVKsAQAAA";

    // test vector, one revocation on index 1
    const BITSTRING_ONE_REVOCATION: &str =
        "H4sIAAAAAAAA_-3AsQAAAAACsNDypwqjZ2sAAAAAAAAAAAAAAAAAAACAtwE3F1_NAEAAAA";

    #[test]
    fn test_generate_bitstring() {
        assert_eq!(
            generate_bitstring(vec![false, true, false, false]).unwrap(),
            BITSTRING_ONE_REVOCATION
        );
    }

    #[test]
    fn test_extract_bitstring_index_success() {
        assert!(!extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 0).unwrap());
        assert!(extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 1).unwrap());

        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS.to_owned(), 0).unwrap());
        assert!(!extract_bitstring_index(BITSTRING_NO_REVOCATIONS.to_owned(), 1).unwrap());
    }

    #[test]
    fn test_extract_bitstring_invalid_base64() {
        let result = extract_bitstring_index("invalid".to_owned(), 1000000);
        assert!(matches!(result, Err(BitstringError::Base64Error(_))));
    }

    #[test]
    fn test_extract_bitstring_index_out_of_bounds() {
        let result = extract_bitstring_index(BITSTRING_ONE_REVOCATION.to_owned(), 1000000);
        assert!(matches!(result, Err(BitstringError::IoError(_))));
    }
}
