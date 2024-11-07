use futures::FutureExt;

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
            let oidc_service = core.oidc_service.clone();
            let callback = Some(
                async move {
                    oidc_service
                        .oidc_verifier_ble_mqtt_presentation(request)
                        .await;
                }
                .boxed(),
            );

            let response = core.proof_service.share_proof(&request, callback).await?;

            Ok(ShareProofResponseBindingDTO::from(response))
        })
    }
}
