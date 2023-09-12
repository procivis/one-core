use crate::{utils::run_sync, ActiveProof, OneCore};
use one_core::model::credential::CredentialId;
use std::str::FromStr;
use uuid::Uuid;

pub use one_core::service::error::ServiceError;

impl OneCore {
    pub fn holder_submit_proof(&self, credential_ids: Vec<String>) -> Result<(), ServiceError> {
        run_sync(async {
            let active_proof = self.active_proof.read().await;
            if let Some(ActiveProof {
                id,
                base_url,
                did_id,
            }) = &*active_proof
            {
                let credential_ids = credential_ids
                    .iter()
                    .map(|id| {
                        Uuid::from_str(id).map_err(|e| ServiceError::MappingError(e.to_string()))
                    })
                    .collect::<Result<Vec<CredentialId>, ServiceError>>()?;

                self.inner
                    .ssi_holder_service
                    .submit_proof("PROCIVIS_TEMPORARY", base_url, id, &credential_ids, did_id)
                    .await?;
            } else {
                return Err(ServiceError::NotFound);
            }

            Ok(())
        })
    }
}
