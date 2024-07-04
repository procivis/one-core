use crate::{dto::CheckInvitationResponseBindingDTO, error::BindingError, OneCoreBinding};
use url::Url;

impl OneCoreBinding {
    pub fn check_invitation(
        &self,
        url: String,
    ) -> Result<CheckInvitationResponseBindingDTO, BindingError> {
        let url = Url::parse(&url).map_err(|e| BindingError::ValidationError(e.to_string()))?;

        self.block_on(async {
            let core = self.use_core().await?;
            let invitation_response = core.ssi_holder_service.check_invitation(url).await?;

            Ok(invitation_response.into())
        })
    }
}
