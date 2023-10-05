use crate::{
    dto::ProofRequestBindingDTO,
    utils::{into_uuid, run_sync},
    OneCoreBinding,
};
use one_core::service::error::ServiceError;

impl OneCoreBinding {
    pub fn get_proof(&self, proof_id: String) -> Result<ProofRequestBindingDTO, ServiceError> {
        run_sync(async {
            let proof = self
                .inner
                .proof_service
                .get_proof(&into_uuid(&proof_id)?)
                .await?;
            Ok(proof.into())
        })
    }
}
