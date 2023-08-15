use crate::{
    utils::{run_sync, TimestampFormat},
    ActiveProof, OneCore,
};

pub use one_core::error::OneCoreError;
use one_core::{
    data_model::{ConnectVerifierResponse, ProofClaimSchema},
    handle_invitation::InvitationResponse,
};

use super::{ClaimDataType, CredentialSchema};

pub struct ProofRequest {
    pub claims: Vec<ProofRequestClaim>,
}

impl From<ConnectVerifierResponse> for ProofRequest {
    fn from(value: ConnectVerifierResponse) -> Self {
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
    pub data_type: ClaimDataType,
    pub required: bool,
    pub credential_schema: CredentialSchema,
}

impl From<ProofClaimSchema> for ProofRequestClaim {
    fn from(value: ProofClaimSchema) -> Self {
        Self {
            id: value.id,
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
    pub fn handle_invitation(&self, url: String) -> Result<HandleInvitationResponse, OneCoreError> {
        run_sync(async {
            Ok(match self.inner.handle_invitation(&url).await? {
                InvitationResponse::Credential {
                    issued_credential_id,
                } => HandleInvitationResponse::InvitationResponseCredentialIssuance {
                    issued_credential_id,
                },
                InvitationResponse::ProofRequest {
                    proof_id,
                    proof_request,
                    base_url,
                } => {
                    let mut active_proof = self.active_proof.write().await;
                    *active_proof = Some(ActiveProof {
                        id: proof_id,
                        base_url,
                    });

                    HandleInvitationResponse::InvitationResponseProofRequest {
                        proof_request: proof_request.into(),
                    }
                }
            })
        })
    }
}
