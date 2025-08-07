use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId, IdentifierId, KeyId, OrganisationId, ProofId};
use strum::Display;
use url::Url;

use crate::model::interaction::InteractionId;
use crate::provider::issuance_protocol::openid4vci_draft13::model::{
    OpenID4VCIProofTypeSupported, OpenID4VCITxCode,
};

#[derive(Clone, Debug)]
pub struct PresentationSubmitRequestDTO {
    pub interaction_id: InteractionId,
    pub submit_credentials: HashMap<String, PresentationSubmitCredentialRequestDTO>,
    pub did_id: Option<DidId>,
    pub identifier_id: Option<IdentifierId>,
    pub key_id: Option<KeyId>,
}

#[derive(Clone, Debug)]
pub struct PresentationSubmitCredentialRequestDTO {
    pub credential_id: CredentialId,
    pub submit_claims: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CredentialConfigurationSupportedResponseDTO {
    pub proof_types_supported: Option<HashMap<String, OpenID4VCIProofTypeSupported>>,
}

#[derive(Clone, Debug)]
pub enum HandleInvitationResultDTO {
    Credential {
        interaction_id: InteractionId,
        credential_ids: Vec<CredentialId>,
        tx_code: Option<OpenID4VCITxCode>,
        credential_configurations_supported:
            HashMap<CredentialId, CredentialConfigurationSupportedResponseDTO>,
    },
    ProofRequest {
        interaction_id: InteractionId,
        proof_id: ProofId,
    },
}

#[derive(Clone, Debug)]
pub struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub credential_ids: Vec<CredentialId>,
    pub credential_configurations_supported:
        HashMap<CredentialId, CredentialConfigurationSupportedResponseDTO>,
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InitiateIssuanceAuthorizationDetailDTO {
    pub r#type: String,
    pub credential_configuration_id: String,
}

#[derive(Clone, Debug)]
pub struct InitiateIssuanceResponseDTO {
    pub url: String,
}

/// <https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata>
///
/// [RFC8414](https://datatracker.ietf.org/doc/html/rfc8414#section-2)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OpenIDAuthorizationServerMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Url,

    #[serde(default)]
    pub code_challenge_methods_supported: Vec<OAuthCodeChallengeMethod>,
}

/// [IANA registry](https://www.iana.org/assignments/oauth-parameters/oauth-parameters.xhtml#pkce-code-challenge-method)
///
/// [RFC7636](https://www.rfc-editor.org/rfc/rfc7636.html#section-4.2)
#[derive(Clone, Copy, Debug, Display, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OAuthCodeChallengeMethod {
    #[serde(rename = "plain")]
    #[strum(serialize = "plain")]
    Plain,
    #[serde(rename = "S256")]
    #[strum(serialize = "S256")]
    S256,
}

/// Interaction data stored on holder side for the OpenID Authorization code flow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct OpenIDAuthorizationCodeFlowInteractionData {
    pub request: InitiateIssuanceRequestDTO,
    pub code_verifier: Option<String>,
}
