use crate::model::revocation_list::RevocationList;
use crate::provider::credential_formatter::error::FormatterError;
use crate::service::error::ServiceError;

impl RevocationList {
    pub fn get_status_credential(&self) -> Result<String, ServiceError> {
        Ok(String::from_utf8(self.credentials.clone())
            .map_err(|e| FormatterError::CouldNotExtractCredentials(e.to_string()))?)
    }
}
