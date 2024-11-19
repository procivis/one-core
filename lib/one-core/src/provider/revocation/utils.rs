use std::io::{Read, Write};

use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;

pub(super) fn gzip_compress(input: Vec<u8>) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = GzEncoder::new(Vec::new(), Default::default());
    encoder.write_all(&input)?;
    encoder.finish()
}

pub(super) fn gzip_decompress(input: Vec<u8>, index: usize) -> Result<Vec<u8>, std::io::Error> {
    let mut decoder = GzDecoder::new(&input[..]);
    let mut result: Vec<u8> = vec![0; index / 8 + 1];
    decoder.read_exact(&mut result)?;
    Ok(result)
}
