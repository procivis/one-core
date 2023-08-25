use std::str::FromStr;

use uuid::Uuid;

use crate::{
    data_model::{ConnectVerifierRequest, ConnectVerifierResponse, ProofClaimSchema},
    error::{OneCoreError, SSIError},
    model::did::DidType,
    repository::{data_provider::ProofRequestState, error::DataLayerError},
    service::{did::dto::CreateDidRequestDTO, error::ServiceError},
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

        if proof_request.state != ProofRequestState::Pending {
            return Err(OneCoreError::SSIError(SSIError::IncorrectProofState));
        }

        let did_id = match self.did_service.get_did_by_value(&request.did).await {
            Ok(did) => did.id,
            Err(ServiceError::NotFound) => {
                self.did_service
                    .create_did(CreateDidRequestDTO {
                        name: "TODO".to_string(),
                        organisation_id: Uuid::from_str(&proof_request.schema.organisation_id)
                            .map_err(|_| {
                                ServiceError::MappingError("Could not convert to UUID".to_string())
                            })?,
                        did: request.did.clone(),
                        did_method: "KEY".to_string(),
                        did_type: DidType::Remote,
                    })
                    .await?
            }
            Err(e) => {
                return Err(OneCoreError::ServiceError(e));
            }
        };

        if let Some(proof_receiver_did_id) = proof_request.receiver_did_id {
            if proof_receiver_did_id != did_id.to_string() {
                // repeated connection using a different holder did
                return Err(OneCoreError::SSIError(SSIError::IncorrectProofState));
            }
        } else {
            self.data_layer
                .set_proof_receiver_did_id(&proof_request_id, &did_id.to_string())
                .await
                .map_err(OneCoreError::DataLayerError)?;
        }

        let proof_schema = self
            .data_layer
            .get_proof_schema_details(&proof_request.schema.id)
            .await
            .map_err(OneCoreError::DataLayerError)?;

        self.data_layer
            .set_proof_state(&proof_request_id, ProofRequestState::Offered)
            .await?;

        Ok(ConnectVerifierResponse {
            claims: proof_schema
                .claim_schemas
                .into_iter()
                .map(|claim| ProofClaimSchema {
                    id: claim.id,
                    key: claim.key,
                    created_date: claim.created_date,
                    last_modified: claim.last_modified,
                    datatype: claim.datatype,
                    required: claim.is_required,
                    credential_schema: claim.credential_schema,
                })
                .collect(),
        })
    }
}
