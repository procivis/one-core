use shared_types::OrganisationId;
use url::Url;

use super::SSIHolderService;
use super::dto::HandleInvitationResultDTO;
use super::error::HolderServiceError;
use crate::error::ContextWithErrorCode;
use crate::service::storage_proxy::StorageProxyImpl;
use crate::validator::throw_if_org_not_matching_session;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        url: Url,
        organisation_id: OrganisationId,
        transport: Option<Vec<String>>,
        redirect_uri: Option<String>,
    ) -> Result<HandleInvitationResultDTO, HolderServiceError> {
        throw_if_org_not_matching_session(&organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&organisation_id, &Default::default())
            .await
            .error_while("getting organisation")?
            .ok_or(HolderServiceError::MissingOrganisation(organisation_id))?;

        if organisation.deactivated_at.is_some() {
            return Err(HolderServiceError::OrganisationIsDeactivated(
                organisation_id,
            ));
        }

        if let Some((issuance_exchange, issuance_protocol)) =
            self.issuance_protocol_provider.detect_protocol(&url).await
        {
            let result = self
                .handle_issuance_invitation(
                    url,
                    organisation,
                    issuance_exchange,
                    issuance_protocol,
                    redirect_uri,
                )
                .await?;
            success_log(&result);
            return Ok(result);
        }

        let result = self
            .handle_verification_invitation(url, organisation, transport)
            .await?;
        success_log(&result);
        Ok(result)
    }

    pub(super) fn storage_proxy(&self) -> StorageProxyImpl {
        StorageProxyImpl::new(
            self.interaction_repository.clone(),
            self.credential_schema_repository.clone(),
            self.credential_repository.clone(),
        )
    }
}

fn success_log(result: &HandleInvitationResultDTO) {
    match result {
        HandleInvitationResultDTO::Credential {
            interaction_id,
            protocol,
            ..
        } => tracing::info!(
            "Handled invitation and created interaction {interaction_id} for credential issuance using pre-authorized code flow: issuance protocol `{protocol}`",
        ),
        HandleInvitationResultDTO::AuthorizationCodeFlow { interaction_id, .. } => tracing::info!(
            "Handled invitation and created interaction {interaction_id} for credential issuance using authorization code flow",
        ),
        HandleInvitationResultDTO::ProofRequest {
            interaction_id,
            proof_id,
            protocol,
        } => tracing::info!(
            "Handled invitation and created interaction {interaction_id} for proof request {proof_id}: verification protocol `{protocol}`"
        ),
    }
}
