use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, EcosystemId, InteractionId, OrganisationId, ProofId, TransactionDataId,
};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode};
use url::Url;

use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::interaction::InteractionType;

#[derive(Clone, Debug)]
pub struct HandleInvitationRequestDTO {
    pub url: Url,
    pub organisation_id: OrganisationId,
    pub transport: Option<Vec<String>>,
    pub redirect_uri: Option<String>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct IssuanceAcceptResponseDTO {
    /// first accepted credential, kept for the single credential API
    pub id: CredentialId,
    /// one main credential per accepted credential configuration
    pub credential_ids: Vec<CredentialId>,
    /// some of the offered credential configurations could not be issued, only set when several were offered
    pub partially_successful: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2RequestDTO {
    pub interaction_id: InteractionId,
    pub submission: HashMap<String, Vec<PresentationSubmitV2CredentialRequestDTO>>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitV2CredentialRequestDTO {
    /// Submitted credential.
    pub credential_id: CredentialId,
    /// Path of claims that were optionally selected by the user.
    pub user_selections: Vec<String>,
    /// Optional ids of transaction-data entries to be included in the presentation of this credential.
    /// Entries not listed here are auto-assigned. Ids must reference transaction
    /// data applicable to this credential.
    pub transaction_data_ids: Vec<TransactionDataId>,
}

#[derive(Clone, Debug)]
pub enum HandleInvitationResultDTO {
    Credential {
        interaction_id: InteractionId,
        tx_code: Option<TxCode>,
        key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
        key_algorithms: Option<Vec<String>>,
        protocol: String,
        requires_wallet_instance_attestation: bool,
        ecosystem: Option<EcosystemId>,
    },
    AuthorizationCodeFlow {
        interaction_id: InteractionId,
        authorization_code_flow_url: String,
        protocol: String,
        ecosystem: Option<EcosystemId>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
        protocol: String,
        ecosystem: Option<EcosystemId>,
    },
}

#[derive(Clone, Debug)]
pub struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub interaction_type: InteractionType,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
    pub key_algorithms: Option<Vec<String>>,
    pub requires_wallet_instance_attestation: bool,
    pub protocol: String,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceRequestDTO {
    pub organisation_id: OrganisationId,
    pub protocol: String,
    pub issuer: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<Vec<String>>,
    pub authorization_details: Option<Vec<AuthorizationDetail>>,
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
    pub ecosystem: Option<EcosystemId>,
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
