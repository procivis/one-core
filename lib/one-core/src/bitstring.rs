use std::io::Write;

use bit_vec::BitVec;
use ct_codecs::{Base64, Encoder};
use flate2::write::GzEncoder;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BitstringError {
    #[error("Base64 error: `{0}`")]
    Base64Error(ct_codecs::Error),
    #[error("IO error: `{0}`")]
    IoError(std::io::Error),
}

fn gzip_compress(input: Vec<u8>) -> Result<Vec<u8>, BitstringError> {
    let mut encoder = GzEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&input).map_err(BitstringError::IoError)?;
    encoder.finish().map_err(BitstringError::IoError)
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
    Base64::encode_to_string(compressed).map_err(BitstringError::Base64Error)
}
