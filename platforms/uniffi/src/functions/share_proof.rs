use one_core::config::core_config::TransportType;

use crate::{error::BindingError, utils::into_id, OneCoreBinding, ShareProofResponseBindingDTO};

impl OneCoreBinding {
    pub fn share_proof(
        &self,
        proof_id: String,
    ) -> Result<ShareProofResponseBindingDTO, BindingError> {
        let request = into_id(&proof_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            let response = core.proof_service.share_proof(&request).await?;
            let proof = core.proof_service.get_proof(&request).await?;

            if proof.transport == TransportType::Ble.to_string() {
                let oidc_service = core.oidc_service.clone();

                // TODO (Eugeniu) - revisit once ONE-2754 is finalized
                // We only do this now because all logic related to handling OpenID presentations
                // is centralized in the oidc service.
                tokio::spawn(async move {
                    let _ = oidc_service
                        .clone()
                        .oidc_verifier_ble_presentation(&request)
                        .await;
                });
            }

            Ok(ShareProofResponseBindingDTO::from(response))
        })
    }
}
