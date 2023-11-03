use crate::{
    dto::HandleInvitationResponseBindingEnum,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;
use url::Url;

impl OneCoreBinding {
    pub fn handle_invitation(
        &self,
        url: String,
        did_id: String,
    ) -> Result<HandleInvitationResponseBindingEnum, ServiceError> {
        let url = Url::parse(&url).map_err(|_| ServiceError::IncorrectParameters)?;

        run_sync(async {
            let invitation_response = self
                .inner
                .ssi_holder_service
                .handle_invitation(url, &into_uuid(&did_id)?)
                .await?;

            Ok(invitation_response.into())
        })
    }
}
