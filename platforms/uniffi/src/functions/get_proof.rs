use crate::{dto::ProofRequestBindingDTO, utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn get_proof(&self, proof_id: String) -> Result<ProofRequestBindingDTO, ServiceError> {
        let proof_id = Uuid::parse_str(&proof_id)
            .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;

        run_sync(async {
            let proof = self.inner.proof_service.get_proof(&proof_id).await?;
            Ok(proof.into())
        })
    }
}
