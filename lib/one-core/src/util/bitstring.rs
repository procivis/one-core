use std::io::{Read, Write};

use bit_vec::BitVec;
use ct_codecs::{Base64UrlSafeNoPadding, Decoder, Encoder};
use flate2::{bufread::GzDecoder, write::GzEncoder};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BitstringError {
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
    let compressed = gzip_compress(bytes).map_err(BitstringError::Compression)?;

    Base64UrlSafeNoPadding::encode_to_string(compressed).map_err(BitstringError::Base64Encoding)
}

pub fn extract_bitstring_index(input: String, index: usize) -> Result<bool, BitstringError> {
    let compressed = Base64UrlSafeNoPadding::decode_to_vec(input, None)
        .map_err(BitstringError::Base64Decoding)?;

    let bytes = gzip_decompress(compressed, index).map_err(|err| {
        if err.kind() == std::io::ErrorKind::UnexpectedEof {
            BitstringError::IndexOutOfBounds { index }
        } else {
            BitstringError::Decompression(err)
        }
    })?;

    let bits = BitVec::from_bytes(&bytes);
    Ok(bits[index])
}

fn gzip_compress(input: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&input)?;
    encoder.finish()
}

fn gzip_decompress(input: Vec<u8>, index: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(&input[..]);
    let mut result: Vec<u8> = vec![0; index / 8 + 1];
    decoder.read_exact(&mut result)?;
    Ok(result)
}

fn calculate_bitstring_size(input_size: usize) -> usize {
    const MINIMUM_INPUT_SIZE: usize = 131072;
    std::cmp::max(input_size, MINIMUM_INPUT_SIZE)
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
