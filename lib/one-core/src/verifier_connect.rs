use crate::{
    data_layer::{data_model::ProofRequestState, DataLayerError},
    data_model::{ConnectVerifierRequest, ConnectVerifierResponse, ProofClaimSchema},
    error::{OneCoreError, SSIError},
    OneCore,
};

impl OneCore {
    pub async fn verifier_connect(
        &self,
        transport_protocol: &str,
        request: &ConnectVerifierRequest,
    ) -> Result<ConnectVerifierResponse, OneCoreError> {
        // Not used for now
        let _transport = self.get_transport_protocol(transport_protocol)?;

        let proof_request_id = request.proof.to_string();

        let proof_request = self
            .data_layer
            .get_proof_details(&proof_request_id)
            .await
            .map_err(|e| match e {
                DataLayerError::RecordNotFound => OneCoreError::SSIError(SSIError::MissingProof),
                e => OneCoreError::DataLayerError(e),
            })?;

        if proof_request.state != ProofRequestState::Offered {
            return Err(OneCoreError::SSIError(SSIError::IncorrectProofState));
        }

        let did_id = match self.data_layer.get_did_details_by_value(&request.did).await {
            Ok(did) => did.id,
            Err(DataLayerError::RecordNotFound) => self
                .data_layer
                .insert_remote_did(&request.did, &proof_request.organisation_id)
                .await
                .map_err(OneCoreError::DataLayerError)?,
            Err(e) => {
                return Err(OneCoreError::DataLayerError(e));
            }
        };

        if let Some(proof_receiver_did_id) = proof_request.receiver_did_id {
            if proof_receiver_did_id != did_id {
                // repeated connection using a different holder did
                return Err(OneCoreError::SSIError(SSIError::IncorrectProofState));
            }
        } else {
            self.data_layer
                .set_proof_receiver_did_id(&proof_request_id, &did_id)
                .await
                .map_err(OneCoreError::DataLayerError)?;
        }

        let proof_schema = self
            .data_layer
            .get_proof_schema_details(&proof_request.schema.id)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        Ok(ConnectVerifierResponse {
            claims: proof_schema
                .claim_schemas
                .into_iter()
                .map(|claim| ProofClaimSchema {
                    id: claim.id,
                    key: claim.key,
                    created_date: claim.created_date,
                    last_modified: claim.last_modified,
                    datatype: claim.datatype.into(),
                    required: claim.is_required,
                    credential_schema: claim.credential_schema,
                })
                .collect(),
        })
    }
}
