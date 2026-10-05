use serde::Deserialize;
use shared_types::{InteractionId, OrganisationId, SerializedCredential, TaskId};
use standardized_types::openid4vci::{AuthorizationDetail, TxCode};
use time::OffsetDateTime;
use uuid::Uuid;

use super::error::IssuanceProtocolError;
use crate::model::credential::{Credential, CredentialType};
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
    pub credential_configuration_id: String,
    pub main_credential: CredentialWithBlob,
    pub batch_items: Vec<CredentialWithBlob>,
}

#[derive(Clone, Debug)]
pub(crate) struct IssuanceRefreshResponse {
    pub credential_configuration_id: String,
    pub credentials: Vec<Credential>,
}

#[derive(Debug, Default)]
pub(crate) struct IssuanceAcceptResult {
    pub issued: Vec<IssuanceAcceptResponse>,
    /// configurations the issuer did not issue a credential for
    pub failed: Vec<IssuanceAcceptFailure>,
}

impl IssuanceAcceptResult {
    pub fn record(
        &mut self,
        credential_configuration_id: &str,
        accepted: Result<IssuanceAcceptResponse, IssuanceProtocolError>,
    ) {
        match accepted {
            Ok(response) => self.issued.push(response),
            Err(error) => self.failed.push(IssuanceAcceptFailure {
                credential_configuration_id: credential_configuration_id.to_owned(),
                error,
            }),
        }
    }
}

#[derive(Debug)]
pub(crate) struct IssuanceAcceptFailure {
    pub credential_configuration_id: String,
    pub error: IssuanceProtocolError,
}

#[derive(Clone, Debug)]
pub(crate) struct CredentialWithBlob {
    pub credential: Credential,
    pub serialized: Option<SerializedCredential>,
}

impl CredentialWithBlob {
    pub fn batch_parent(&self, refreshable: bool) -> Self {
        Self {
            credential: {
                let mut updated_credential = self.credential.clone();
                updated_credential.common_mut().id = Uuid::new_v4().into();
                updated_credential.common_mut().expires_at = if refreshable {
                    None
                } else {
                    self.credential.common().expires_at
                };
                *updated_credential.type_mut() = CredentialType::BatchParent;
                *updated_credential.embedded_disclosure_policy_mut() = None;
                *updated_credential.format_mut() = None;
                *updated_credential.credential_blob_id_mut() = None;
                *updated_credential.wallet_instance_attestation_blob_id_mut() = None;
                *updated_credential.wallet_key_attestation_blob_id_mut() = None;
                *updated_credential.issuer_identifier_mut() = None;
                *updated_credential.issuer_certificate_mut() = None;
                *updated_credential.holder_identifier_mut() = None;
                *updated_credential.key_mut() = None;
                *updated_credential.claims_mut() = Default::default();
                updated_credential
            },
            serialized: None,
        }
    }
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
