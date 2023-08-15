use crate::error::SSIError;
use crate::{error::OneCoreError, OneCore};

impl OneCore {
    pub async fn holder_reject_proof_request(
        &self,
        transport_protocol: &str,
        base_url: &str,
        proof_id: &str,
    ) -> Result<(), OneCoreError> {
        self.get_transport_protocol(transport_protocol)?
            .reject_proof(base_url, proof_id)
            .await
            .map_err(|e| OneCoreError::SSIError(SSIError::TransportProtocolError(e)))
    }
}
