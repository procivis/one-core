use crate::error::OneCoreError;
use crate::OneCore;

impl OneCore {
    pub async fn reject_proof_request(&self, proof_request_id: &str) -> Result<(), OneCoreError> {
        self.data_layer
            .reject_proof_request(proof_request_id)
            .await
            .map_err(OneCoreError::DataLayerError)
    }
}
