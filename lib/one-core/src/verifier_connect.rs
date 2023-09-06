use crate::{
    data_model::{ConnectVerifierRequest, ConnectVerifierResponse, ProofClaimSchema},
    error::{OneCoreError, SSIError},
    service::error::ServiceError,
    OneCore,
};

impl OneCore {
    pub async fn verifier_connect(
        &self,
        // transport_protocol: &str,
        request: &ConnectVerifierRequest,
    ) -> Result<ConnectVerifierResponse, OneCoreError> {
        // Not used for now
        //  let _transport = self.get_transport_protocol(transport_protocol)?;

        let proof = self
            .proof_service
            .get_proof(&request.proof)
            .await
            .map_err(|e| match e {
                ServiceError::NotFound => OneCoreError::SSIError(SSIError::MissingProof),
                e => OneCoreError::ServiceError(e),
            })?;

        let proof_schema_id = proof.schema.id;

        let proof_schema = self
            .proof_schema_service
            .get_proof_schema(&proof_schema_id)
            .await
            .map_err(OneCoreError::ServiceError)?;

        self.proof_service
            .set_holder_connected(&request.proof, &request.did)
            .await
            .map_err(|e| match e {
                ServiceError::AlreadyExists => {
                    OneCoreError::SSIError(SSIError::IncorrectProofState)
                }
                e => OneCoreError::ServiceError(e),
            })?;

        Ok(ConnectVerifierResponse {
            claims: proof_schema
                .claim_schemas
                .into_iter()
                .map(|claim| ProofClaimSchema {
                    id: claim.id.to_string(),
                    key: claim.key,
                    created_date: claim.credential_schema.created_date,
                    last_modified: claim.credential_schema.last_modified,
                    datatype: claim.data_type,
                    required: claim.required,
                    credential_schema: claim.credential_schema.into(),
                })
                .collect(),
        })
    }
}
