use time::{Duration, OffsetDateTime};

use crate::provider::signer::dto::CreateSignatureRequestDTO;
use crate::provider::signer::error::SignerError;

pub(super) struct SignatureValidity {
    pub start: OffsetDateTime,
    pub end: OffsetDateTime,
}
pub(super) fn calculate_signature_validity(
    max_validity: Duration,
    request: &CreateSignatureRequestDTO,
) -> Result<SignatureValidity, SignerError> {
    let now = OffsetDateTime::now_utc();
    let start = match request.validity_start {
        None => now,
        Some(start) => {
            if start < now {
                return Err(SignerError::ValidityBoundaryInThePast {
                    validity_boundary: start,
                });
            }
            start
        }
    };
    let end = match request.validity_end {
        None => start + max_validity,
        Some(end) => {
            if end < now {
                return Err(SignerError::ValidityBoundaryInThePast {
                    validity_boundary: end,
                });
            }
            if end < start {
                return Err(SignerError::ValidityStartAfterEnd {
                    validity_start: start,
                    validity_end: end,
                });
            }
            if end - start > max_validity {
                return Err(SignerError::ValidityPeriodTooLong {
                    validity_start: start,
                    validity_end: end,
                    max_duration: max_validity,
                });
            }
            end
        }
    };
    Ok(SignatureValidity { start, end })
}
