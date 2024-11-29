use one_core::service::error::ServiceError;
use url::Url;

use crate::dto::HandleInvitationResponseBindingEnum;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::OneCoreBinding;

impl OneCoreBinding {
    pub fn handle_invitation(
        &self,
        url: String,
        organisation_id: String,
        transport: Option<Vec<String>>,
    ) -> Result<HandleInvitationResponseBindingEnum, BindingError> {
        let url = Url::parse(&url).map_err(|e| ServiceError::ValidationError(e.to_string()))?;

        self.block_on(async {
            let organisation_id = into_id(&organisation_id)?;

            let core = self.use_core().await?;
            let invitation_response = core
                .ssi_holder_service
                .handle_invitation(url, organisation_id, transport)
                .await?;

            Ok(invitation_response.into())
        })
    }
}
