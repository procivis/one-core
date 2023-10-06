use std::sync::Arc;

use crate::{
    credential_formatter::FormatterError,
    crypto::{hasher::Hasher, Crypto},
};

use super::{get_temp_keys, mapper::*, models::Disclosure};

pub(super) fn verify_claims(
    hashed_claims: &[String],
    disclosures: &[(Disclosure, String)],
    hasher: &Arc<dyn Hasher + Send + Sync>,
) -> Result<(), FormatterError> {
    if !disclosures.iter().all(|disclosure| {
        hashed_claims.contains(
            &hasher
                .hash_base64(disclosure.1.as_bytes())
                .unwrap_or_default(),
        )
    }) {
        return Err(FormatterError::MissingClaim);
    }
    Ok(())
}

pub(super) fn verify_signature(
    crypto: &Crypto,
    header_json: &str,
    payload_json: &str,
    signature: &[u8],
    signature_algorithm: &str,
) -> Result<(), FormatterError> {
    let signer = crypto
        .signers
        .get(signature_algorithm)
        .ok_or(FormatterError::MissingSigner)?;

    let (_, public) = get_temp_keys();

    let jwt = format!(
        "{}.{}",
        string_to_b64url_string(header_json)?,
        string_to_b64url_string(payload_json)?,
    );

    signer.verify(&jwt, signature, &public)?;
    Ok(())
}
