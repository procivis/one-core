use std::io::{Read, Write};

use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;

use crate::provider::revocation::error::RevocationError;
use crate::provider::revocation::model::CredentialRevocationState;

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

pub(super) fn status_purpose_to_revocation_state(
    status_purpose: Option<&String>,
) -> Result<CredentialRevocationState, RevocationError> {
    match status_purpose
        .ok_or(RevocationError::ValidationError(
            "Missing status purpose ".to_string(),
        ))?
        .as_str()
    {
        "revocation" => Ok(CredentialRevocationState::Revoked),
        "suspension" => Ok(CredentialRevocationState::Suspended {
            suspend_end_date: None,
        }),
        value => Err(RevocationError::ValidationError(format!(
            "Invalid status purpose: {value}",
        ))),
    }
}
