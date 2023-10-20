use std::sync::Arc;

use crate::{crypto::hasher::Hasher, provider::credential_formatter::FormatterError};

use super::models::Disclosure;

pub(super) fn verify_claims(
    hashed_claims: &[String],
    disclosures: &[(Disclosure, String, String)],
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
