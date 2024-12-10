use futures::FutureExt;

use crate::dto::ShareProofRequestBindingDTO;
use crate::error::BindingError;
use crate::utils::into_id;
use crate::{OneCoreBinding, ShareProofResponseBindingDTO};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn share_proof(
        &self,
        proof_id: String,
        params: ShareProofRequestBindingDTO,
    ) -> Result<ShareProofResponseBindingDTO, BindingError> {
        let id = into_id(&proof_id)?;
        let request = params.into();

        self.block_on(async {
            let core = self.use_core().await?;
            let oidc_service = core.oidc_service.clone();
            let callback = Some(
                async move {
                    oidc_service.oidc_verifier_ble_mqtt_presentation(id).await;
                }
                .boxed(),
            );

            let response = core
                .proof_service
                .share_proof(&id, request, callback)
                .await?;

            Ok(ShareProofResponseBindingDTO::from(response))
        })
    }
}
