use serde::Deserialize;
use shared_types::{InteractionId, OrganisationId, SerializedCredential, TaskId};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode};
use time::OffsetDateTime;

use crate::model::credential::Credential;
use crate::model::credential_schema::KeyStorageSecurity;
use crate::provider::ecosystem::model::ProtocolArtifact;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRedirectUriParams {
    pub enabled: bool,
    pub allowed_schemes: Vec<String>,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
pub(super) fn default_issuance_url_scheme() -> String {
    "openid-credential-offer".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CommonParams {
    pub webhook_task: Option<TaskId>,
}

#[derive(Clone, Debug)]
pub(crate) enum InvitationResponseEnum<'a> {
    Credential {
        interaction_id: InteractionId,
        tx_code: Option<TxCode>,
        key_storage_security: Option<Vec<KeyStorageSecurity>>,
        key_algorithms: Option<Vec<String>>,
        requires_wallet_instance_attestation: bool,
        ecosystem_artifact: ProtocolArtifact<'a>,
    },
    AuthorizationFlow {
        organisation_id: OrganisationId,
        issuer: String,
        client_id: String,
        redirect_uri: Option<String>,
        authorization_details: Option<Vec<AuthorizationDetail>>,
        issuer_state: Option<String>,
        scope: Option<Vec<String>>,
        authorization_server: Option<String>,
        ecosystem_artifact: ProtocolArtifact<'a>,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct IssuanceAcceptResponse {
    pub main_credential: CredentialWithBlob,
    pub batch_items: Vec<CredentialWithBlob>,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialWithBlob {
    pub credential: Credential,
    pub serialized: Option<SerializedCredential>,
}

#[derive(Clone, Deserialize, Debug)]
pub(crate) struct SubmitIssuerResponse {
    pub credentials: Vec<SerializedCredential>,
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ShareResponse {
    pub url: String,
    pub interaction_id: InteractionId,
    pub interaction_data: Option<Vec<u8>>,
    pub expires_at: Option<OffsetDateTime>,
    pub transaction_code: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ContinueIssuanceResponseDTO<'a> {
    pub interaction_id: InteractionId,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
    pub key_algorithms: Option<Vec<String>>,
    pub requires_wallet_instance_attestation: bool,
    pub protocol: String,
    pub ecosystem_artifact: ProtocolArtifact<'a>,
}
