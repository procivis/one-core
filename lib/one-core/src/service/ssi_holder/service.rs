use shared_types::OrganisationId;
use url::Url;

use super::dto::HandleInvitationResultDTO;
use super::SSIHolderService;
use crate::service::error::{EntityNotFoundError, ServiceError};

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation_id: OrganisationId,
        transport: Option<Vec<String>>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(organisation_id))?;

        if let Some((issuance_exchange, issuance_protocol)) =
            self.issuance_protocol_provider.detect_protocol(&url)
        {
            return self
                .handle_issuance_invitation(url, organisation, issuance_exchange, issuance_protocol)
                .await;
        }

        self.handle_verification_invitation(url, organisation, transport)
            .await
    }
}
