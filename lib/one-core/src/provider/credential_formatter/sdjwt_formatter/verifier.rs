use super::disclosures::{gather_hashes_from_disclosures, gather_hashes_from_hashed_claims};
use super::model::Disclosure;
use one_crypto::Hasher;
use crate::provider::credential_formatter::error::FormatterError;

pub(super) fn verify_claims(
    hashed_claims: &[String],
    disclosures: &[Disclosure],
    hasher: &dyn Hasher,
) -> Result<(), FormatterError> {
    let mut hashes_used_by_disclosures = gather_hashes_from_disclosures(disclosures, hasher)?;

    let mut hashes_found_in_hashed_claims =
        gather_hashes_from_hashed_claims(hashed_claims, disclosures, hasher)?;

    hashes_used_by_disclosures.sort_unstable();
    hashes_found_in_hashed_claims.sort_unstable();

    Ok(())
}
