use one_core::config::core_config::TransportType;

use crate::error::BindingError;
use crate::utils::into_id;
use crate::{OneCoreBinding, ShareProofResponseBindingDTO};

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

            if [
                TransportType::Ble.as_ref(),
                TransportType::Mqtt.as_ref(),
                "",
            ]
            .contains(&proof.transport.as_str())
            {
                let oidc_service = core.oidc_service.clone();

                // TODO (Eugeniu) - revisit once ONE-2754 is finalized
                // We only do this now because all logic related to handling OpenID presentations
                // is centralized in the oidc service.
                tokio::spawn(async move {
                    let _ = oidc_service
                        .oidc_verifier_ble_mqtt_presentation(&request)
                        .await;
                });
            }

            Ok(ShareProofResponseBindingDTO::from(response))
        })
    }
}
