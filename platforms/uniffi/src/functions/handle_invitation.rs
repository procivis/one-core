use crate::{dto::HandleInvitationResponseBindingEnum, utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn handle_invitation(
        &self,
        url: String,
        did_id: String,
    ) -> Result<HandleInvitationResponseBindingEnum, ServiceError> {
        let did_id = Uuid::parse_str(&did_id)
            .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;

        run_sync(async {
            let invitation_response = self
                .inner
                .ssi_holder_service
                .handle_invitation(&url, &did_id)
                .await?;

            Ok(invitation_response.into())
        })
    }
}
