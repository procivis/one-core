use crate::{
    dto::HandleInvitationResponseBindingEnum,
    error::BindingError,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use url::Url;

impl OneCoreBinding {
    pub fn handle_invitation(
        &self,
        url: String,
        did_id: String,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url = Url::parse(&url).map_err(|e| BindingError::ValidationError(e.to_string()))?;

        run_sync(async {
            let did_id = into_uuid(&did_id)?.into();

            let core = self.use_core().await?;
            let invitation_response = core
                .ssi_holder_service
                .handle_invitation(url, &did_id)
                .await?;

            Ok(invitation_response.into())
        })
    }
}
