use crate::model::revocation_list::RevocationListEntryStatus;
use crate::service::signature::dto::SignatureState;
use crate::service::signature::error::SignatureServiceError;

impl TryFrom<RevocationListEntryStatus> for SignatureState {
    type Error = SignatureServiceError;

    fn try_from(value: RevocationListEntryStatus) -> Result<Self, Self::Error> {
        match value {
            RevocationListEntryStatus::Active => Ok(Self::Active),
            RevocationListEntryStatus::Revoked => Ok(Self::Revoked),
            RevocationListEntryStatus::Suspended => Err(SignatureServiceError::MappingError(
                format!("Invalid signature revocation status: {:?}", value),
            )),
        }
    }
}
