use shared_types::OrganisationId;
use url::Url;

use super::SSIHolderService;
use super::dto::HandleInvitationResultDTO;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation_id: OrganisationId,
        transport: Option<Vec<String>>,
        redirect_uri: Option<String>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(BusinessLogicError::OrganisationIsDeactivated(organisation_id).into());
        }

        if let Some((issuance_exchange, issuance_protocol)) =
            self.issuance_protocol_provider.detect_protocol(&url)
        {
            return self
                .handle_issuance_invitation(
                    url,
                    organisation,
                    issuance_exchange,
                    issuance_protocol,
                    redirect_uri,
                )
                .await;
        }

        self.handle_verification_invitation(url, organisation, transport)
            .await
    }
}
