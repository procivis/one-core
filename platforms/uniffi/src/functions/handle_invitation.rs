use crate::{
    dto::HandleInvitationResponseBindingEnum, error::BindingError, utils::into_id, OneCoreBinding,
};
use url::Url;

impl OneCoreBinding {
    pub fn handle_invitation(
        &self,
        url: String,
        organisation_id: String,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url = Url::parse(&url).map_err(|e| BindingError::ValidationError(e.to_string()))?;

        self.block_on(async {
            let organisation_id = into_id(&organisation_id)?;

            let core = self.use_core().await?;
            let invitation_response = core
                .ssi_holder_service
                .handle_invitation(url, organisation_id)
                .await?;

            Ok(invitation_response.into())
        })
    }
}
