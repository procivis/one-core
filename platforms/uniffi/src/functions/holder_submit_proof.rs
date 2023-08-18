use crate::{utils::run_sync, ActiveProof, OneCore};

pub use one_core::error::OneCoreError;
use one_core::error::SSIError;

impl OneCore {
    pub fn holder_submit_proof(&self, credential_ids: Vec<String>) -> Result<(), OneCoreError> {
        run_sync(async {
            let active_proof = self.active_proof.read().await;
            if let Some(ActiveProof { id, base_url }) = &*active_proof {
                self.inner
                    .holder_submit_proof("PROCIVIS_TEMPORARY", base_url, id, &credential_ids)
                    .await?;
            } else {
                return Err(OneCoreError::SSIError(SSIError::MissingProof));
            }

            Ok(())
        })
    }
}
