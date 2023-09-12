use crate::{utils::run_sync, ActiveProof, OneCoreBinding};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn holder_reject_proof(&self) -> Result<(), ServiceError> {
        run_sync(async {
            let active_proof = self.active_proof.read().await;
            if let Some(ActiveProof { id, base_url, .. }) = &*active_proof {
                self.inner
                    .ssi_holder_service
                    .reject_proof_request("PROCIVIS_TEMPORARY", base_url, id)
                    .await?;
            } else {
                return Err(ServiceError::NotFound);
            }

            Ok(())
        })
    }
}
