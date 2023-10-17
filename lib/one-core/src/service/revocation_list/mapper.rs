use crate::credential_formatter::FormatterError;
use crate::model::revocation_list::RevocationList;
use crate::service::error::ServiceError;

impl TryFrom<RevocationList> for String {
    type Error = ServiceError;
    fn try_from(value: RevocationList) -> Result<Self, Self::Error> {
        Ok(String::from_utf8(value.credentials)
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?)
    }
}
