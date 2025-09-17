use std::collections::HashMap;

use indexmap::IndexMap;
use secrecy::SecretSlice;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CredentialId, OrganisationId};
use strum::Display;
use uuid::Uuid;

use crate::config::core_config::KeyAlgorithmType;
use crate::model::certificate::Certificate;
use crate::model::credential::{Credential, UpdateCredentialRequest};
use crate::model::credential_schema::UpdateCredentialSchemaRequest;
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::interaction::InteractionId;
use crate::model::key::Key;
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;
use crate::util::params::deserialize_encryption_key;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCIParams {
    pub pre_authorized_code_expires_in: u64,
    pub token_expires_in: u64,
    pub refresh_expires_in: u64,
    #[serde(default)]
    pub credential_offer_by_value: bool,
    #[serde(deserialize_with = "deserialize_encryption_key")]
    pub encryption: SecretSlice<u8>,

    #[serde(default = "default_issuance_url_scheme")]
    pub url_scheme: String,

    pub redirect_uri: OpenID4VCRedirectUriParams,

    pub rejection_identifier: Option<OpenID4VCRejectionIdentifierParams>,

    #[serde(default = "default_enable_credential_preview")]
    pub enable_credential_preview: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRejectionIdentifierParams {
    pub did_method: String,
    pub key_algorithm: KeyAlgorithmType,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4VCRedirectUriParams {
    pub enabled: bool,
    pub allowed_schemes: Vec<String>,
}

// Apparently the indirection via functions is required: https://github.com/serde-rs/serde/issues/368
fn default_issuance_url_scheme() -> String {
    "openid-credential-offer".to_string()
}

fn default_enable_credential_preview() -> bool {
    true
}

#[derive(Clone, Debug)]
pub(crate) enum InvitationResponseEnum {
    Credential {
        interaction_id: InteractionId,
        credentials: Vec<Credential>,
        tx_code: Option<OpenID4VCITxCode>,
        issuer_proof_type_supported:
            HashMap<CredentialId, Option<IndexMap<String, OpenID4VCIProofTypeSupported>>>,
    },
    AuthorizationFlow {
        organisation_id: OrganisationId,
        issuer: String,
        client_id: String,
        redirect_uri: Option<String>,
        authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailDTO>>,
        issuer_state: Option<String>,
        authorization_server: Option<String>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct OpenID4VCITxCode {
    #[serde(default)]
    pub input_mode: OpenID4VCITxCodeInputMode,
    #[serde(default)]
    pub length: Option<i64>,
    #[serde(default)]
    pub description: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Display, Default)]
pub enum OpenID4VCITxCodeInputMode {
    #[serde(rename = "numeric")]
    #[strum(serialize = "numeric")]
    #[default]
    Numeric,
    #[serde(rename = "text")]
    #[strum(serialize = "text")]
    Text,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct UpdateResponse<T> {
    pub result: T,
    pub create_did: Option<Did>,
    pub create_key: Option<Key>,
    pub create_certificate: Option<Certificate>,
    pub create_identifier: Option<Identifier>,
    pub update_credential: Option<(CredentialId, UpdateCredentialRequest)>,
    pub update_credential_schema: Option<UpdateCredentialSchemaRequest>,
}

#[derive(Clone, Deserialize, Debug)]
pub(crate) struct SubmitIssuerResponse {
    pub credential: String,
    #[serde(rename = "redirectUri")]
    pub redirect_uri: Option<String>,
    pub notification_id: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ShareResponse<T> {
    pub url: String,
    pub interaction_id: Uuid,
    pub context: T,
}

#[derive(Clone, Debug)]
pub(crate) struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub credentials: Vec<Credential>,
    pub issuer_proof_type_supported:
        HashMap<CredentialId, Option<IndexMap<String, OpenID4VCIProofTypeSupported>>>,
}
