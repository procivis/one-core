use crate::OneCore;
use thiserror::Error;

pub struct InvitationResult {
    pub issued_credential_id: String,
}

#[derive(Debug, Error)]
pub enum InvitationError {
    #[error("General invitation error `{0}`")]
    GeneralError(String),
    #[error("Credential Issuance failed")]
    CredentialIssuanceFailure,
}

impl OneCore {
    pub fn handle_invitation(&self, _url: String) -> Result<InvitationResult, InvitationError> {
        Err(InvitationError::GeneralError("Not implemented".to_string()))
    }
}
