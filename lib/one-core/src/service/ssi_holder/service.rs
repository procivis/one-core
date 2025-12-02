use shared_types::OrganisationId;
use url::Url;

use super::SSIHolderService;
use super::dto::HandleInvitationResultDTO;
use crate::service::error::{BusinessLogicError, EntityNotFoundError, ServiceError};
use crate::service::storage_proxy::StorageProxyImpl;
use crate::validator::throw_if_org_not_matching_session;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation_id: OrganisationId,
        transport: Option<Vec<String>>,
        redirect_uri: Option<String>,
    ) -> Result<HandleInvitationResultDTO, ServiceError> {
        throw_if_org_not_matching_session(&organisation_id, &*self.session_provider)?;
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Organisation(organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(BusinessLogicError::OrganisationIsDeactivated(organisation_id).into());
        }

        if let Some((issuance_exchange, issuance_protocol)) =
            self.issuance_protocol_provider.detect_protocol(&url).await
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

    pub(super) fn storage_proxy(&self) -> StorageProxyImpl {
        StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
            self.did_repository.clone(),
            self.certificate_repository.clone(),
            self.key_repository.clone(),
            self.identifier_repository.clone(),
        )
    }
}
