use crate::model::revocation_list::RevocationList;
use crate::provider::revocation::error::RevocationError;

impl RevocationList {
    pub fn get_status_credential(&self) -> Result<String, RevocationError> {
        Ok(String::from_utf8(self.formatted_list.clone())?)
    }
}
