use anyhow::{Context, anyhow};

use super::IdentityRequest;

pub(crate) fn parse_identity_request(data: Vec<u8>) -> anyhow::Result<IdentityRequest> {
    let arr: [u8; 44] = data
        .try_into()
        .map_err(|_| anyhow!("Failed to convert vec to [u8; 44]"))?;

    let (key, nonce) = arr.split_at(32);

    Ok(IdentityRequest {
        key: key
            .try_into()
            .context("Failed to parse key from identity request")?,
        nonce: nonce
            .try_into()
            .context("Failed to parse nonce from identity request")?,
    })
}
