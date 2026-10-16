use super::SSIHolderService;
use super::dto::{HandleInvitationRequestDTO, HandleInvitationResultDTO};
use super::error::HolderServiceError;
use crate::error::ContextWithErrorCode;
use crate::validator::throw_if_org_id_not_matching_session;

impl SSIHolderService {
    pub async fn handle_invitation(
        &self,
        request: HandleInvitationRequestDTO,
    ) -> Result<HandleInvitationResultDTO, HolderServiceError> {
        throw_if_org_id_not_matching_session(&request.organisation_id, &*self.session_provider)
            .error_while("checking session")?;
        let organisation = self
            .organisation_repository
            .get_organisation(&request.organisation_id)
            .await
            .error_while("getting organisation")?;

        if organisation.deactivated_at.is_some() {
            return Err(HolderServiceError::OrganisationIsDeactivated(
                request.organisation_id,
            ));
        }

        let result = if let Some((issuance_exchange, issuance_protocol)) = self
            .issuance_protocol_provider
            .detect_protocol(&request.url)
            .await
        {
            self.handle_issuance_invitation(
                request.url,
                organisation,
                issuance_exchange,
                issuance_protocol,
                request.redirect_uri,
                request.ecosystem,
            )
            .await?
        } else {
            self.handle_verification_invitation(
                request.url,
                organisation,
                request.transport,
                request.ecosystem,
            )
            .await?
        };

        success_log(&result);
        Ok(result)
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
            ..
        } => tracing::info!(
            "Handled invitation and created interaction {interaction_id} for proof request {proof_id}: verification protocol `{protocol}`"
        ),
    }
}
