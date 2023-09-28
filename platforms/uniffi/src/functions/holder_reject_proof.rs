use crate::{utils::run_sync, OneCoreBinding};
use one_core::service::error::ServiceError;
use uuid::Uuid;

impl OneCoreBinding {
    pub fn holder_reject_proof(&self, interaction_id: String) -> Result<(), ServiceError> {
        let interaction_id = Uuid::parse_str(&interaction_id)
            .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;

        run_sync(async {
            self.inner
                .ssi_holder_service
                .reject_proof_request(&interaction_id)
                .await
        })
    }
}
