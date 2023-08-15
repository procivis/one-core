use crate::{utils::run_sync, ActiveProof, OneCore};

pub use one_core::error::OneCoreError;
use one_core::error::SSIError;

impl OneCore {
    pub fn holder_reject_proof(&self) -> Result<(), OneCoreError> {
        run_sync(async {
            let active_proof = self.active_proof.read().await;
            if let Some(ActiveProof { id, base_url }) = &*active_proof {
                self.inner
                    .holder_reject_proof_request("PROCIVIS_TEMPORARY", base_url, id)
                    .await?;
            } else {
                return Err(OneCoreError::SSIError(SSIError::MissingProof));
            }

            Ok(())
        })
    }
}
