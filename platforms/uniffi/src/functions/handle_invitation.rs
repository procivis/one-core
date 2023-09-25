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
            Ok(
                match self
                    .inner
                    .ssi_holder_service
                    .handle_invitation(&url, &did_id)
                    .await?
                {
                    InvitationResponseDTO::Credential {
                        credential_id,
                        interaction_id,
                    } => {
                        let credential = self
                            .inner
                            .credential_service
                            .get_credential(&credential_id)
                            .await?;

                        HandleInvitationResponseBindingEnum::CredentialIssuance {
                            interaction_id: interaction_id.to_string(),
                            credentials: vec![credential.into()],
                        }
                    }
                    InvitationResponseDTO::ProofRequest {
                        proof_id,
                        proof_request,
                        ..
                    } => {
                        // temporary workaround for interaction skip
                        let base_url = get_base_url(&url)?;

                        let mut active_proof = self.active_proof.write().await;
                        *active_proof = Some(ActiveProof {
                            id: proof_id,
                            base_url,
                            did_id,
                        });

                        HandleInvitationResponseBindingEnum::ProofRequest {
                            proof_request: proof_request.into(),
                        }
                    }
                },
            )
        })
    }
}
