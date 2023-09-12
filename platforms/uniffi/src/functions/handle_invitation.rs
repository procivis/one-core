use super::CredentialSchema;
use crate::{
    utils::{run_sync, TimestampFormat},
    ActiveProof, OneCore,
};
use one_core::service::{
    ssi_holder::dto::InvitationResponseDTO,
    ssi_verifier::dto::{ConnectVerifierResponseDTO, ProofRequestClaimDTO},
};
use uuid::Uuid;

pub use one_core::service::error::ServiceError;

pub struct ProofRequest {
    pub claims: Vec<ProofRequestClaim>,
}

impl From<ConnectVerifierResponseDTO> for ProofRequest {
    fn from(value: ConnectVerifierResponseDTO) -> Self {
        Self {
            claims: value.claims.into_iter().map(|claim| claim.into()).collect(),
        }
    }
}

pub struct ProofRequestClaim {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub key: String,
    pub data_type: String,
    pub required: bool,
    pub credential_schema: CredentialSchema,
}

impl From<ProofRequestClaimDTO> for ProofRequestClaim {
    fn from(value: ProofRequestClaimDTO) -> Self {
        Self {
            id: value.id.to_string(),
            created_date: value.created_date.format_timestamp(),
            last_modified: value.last_modified.format_timestamp(),
            key: value.key,
            data_type: value.datatype,
            required: value.required,
            credential_schema: value.credential_schema.into(),
        }
    }
}

pub enum HandleInvitationResponse {
    InvitationResponseCredentialIssuance { issued_credential_id: String },
    InvitationResponseProofRequest { proof_request: ProofRequest },
}

impl OneCore {
    pub fn handle_invitation(
        &self,
        url: String,
        did_id: String,
    ) -> Result<HandleInvitationResponse, ServiceError> {
        let did_id = Uuid::parse_str(&did_id)
            .map_err(|e| ServiceError::GeneralRuntimeError(e.to_string()))?;

        run_sync(async {
            Ok(
                match self
                    .inner
                    .ssi_holder_service
                    .handle_invitation(&url, &did_id)
                    .await?
                {
                    InvitationResponseDTO::Credential {
                        issued_credential_id,
                    } => HandleInvitationResponse::InvitationResponseCredentialIssuance {
                        issued_credential_id: issued_credential_id.to_string(),
                    },
                    InvitationResponseDTO::ProofRequest {
                        proof_id,
                        proof_request,
                        base_url,
                    } => {
                        let mut active_proof = self.active_proof.write().await;
                        *active_proof = Some(ActiveProof {
                            id: proof_id,
                            base_url,
                            did_id,
                        });

                        HandleInvitationResponse::InvitationResponseProofRequest {
                            proof_request: proof_request.into(),
                        }
                    }
                },
            )
        })
    }
}
