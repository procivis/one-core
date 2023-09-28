use crate::{
    dto::HandleInvitationResponseBindingEnum, utils::run_sync, ActiveProof, OneCoreBinding,
};
use one_core::{
    common_mapper::get_base_url,
    service::{error::ServiceError, ssi_holder::dto::InvitationResponseDTO},
};
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

            // temporary workaround for interaction skip
            if let InvitationResponseDTO::ProofRequest { proof_id, .. } = invitation_response {
                let base_url = get_base_url(&url)?;
                let mut active_proof = self.active_proof.write().await;
                *active_proof = Some(ActiveProof {
                    id: proof_id,
                    base_url,
                    did_id,
                });
            }

            Ok(invitation_response.into())
        })
    }
}
