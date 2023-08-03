use crate::{utils::run_sync, OneCore};

pub use one_core::error::OneCoreError;

pub struct InvitationResult {
    pub issued_credential_id: String,
}

impl OneCore {
    pub fn handle_invitation(&self, url: String) -> Result<InvitationResult, OneCoreError> {
        run_sync(async {
            Ok(InvitationResult {
                issued_credential_id: self.inner.handle_invitation(&url).await?,
            })
        })
    }
}
