use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, OrganisationId, ProofId};
use uuid::Uuid;

use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::interaction::{InteractionId, InteractionType};
use crate::provider::issuance_protocol::model::{OpenID4VCIProofTypeSupported, OpenID4VCITxCode};

#[derive(Clone, Debug)]
pub struct PresentationSubmitRequestDTO {
    pub interaction_id: InteractionId,
    pub submit_credentials: HashMap<String, Vec<PresentationSubmitCredentialRequestDTO>>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitCredentialRequestDTO {
    pub credential_id: CredentialId,
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2RequestDTO {
    pub interaction_id: Uuid,
    pub submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestDTO>>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2CredentialRequestDTO {
    /// Submitted credential.
    pub credential_id: CredentialId,
    /// Path of claims that were optionally selected by the user.
    pub user_selections: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CredentialConfigurationSupportedResponseDTO {
    pub proof_types_supported: Option<HashMap<String, OpenID4VCIProofTypeSupported>>,
}

#[derive(Clone, Debug)]
pub enum HandleInvitationResultDTO {
    Credential {
        interaction_id: InteractionId,
        tx_code: Option<OpenID4VCITxCode>,
        key_storage_security: Option<KeyStorageSecurity>,
    },
    AuthorizationCodeFlow {
        interaction_id: InteractionId,
        authorization_code_flow_url: String,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
    },
}

#[derive(Clone, Debug)]
pub struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionType,
    pub key_storage_security: Option<KeyStorageSecurity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub protocol: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<Vec<String>>,
    pub authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailDTO>>,
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceAuthorizationDetailDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug)]
pub struct InitiateIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub url: String,
}

/// Interaction data stored on holder side for the OpenID Authorization code flow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OpenIDAuthorizationCodeFlowInteractionData {
    pub request: InitiateIssuanceRequestDTO,
    pub code_verifier: Option<String>,
}
