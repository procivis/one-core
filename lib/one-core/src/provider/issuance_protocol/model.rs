use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CredentialId, InteractionId, OrganisationId};
use strum::Display;
use time::OffsetDateTime;

use crate::model::certificate::Certificate;
use crate::model::credential::{Credential, UpdateCredentialRequest};
use crate::model::credential_schema::{
    CredentialSchema, KeyStorageSecurity, UpdateCredentialSchemaRequest,
};
use crate::model::did::Did;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::service::ssi_holder::dto::InitiateIssuanceAuthorizationDetailDTO;

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

pub(super) fn default_enable_credential_preview() -> bool {
    true
}

#[derive(Clone, Debug)]
pub(crate) enum InvitationResponseEnum {
    Credential {
        interaction_id: InteractionId,
        tx_code: Option<OpenID4VCITxCode>,
        key_storage_security: Option<Vec<KeyStorageSecurity>>,
        key_algorithms: Option<Vec<String>>,
    },
    AuthorizationFlow {
        organisation_id: OrganisationId,
        issuer: String,
        client_id: String,
        redirect_uri: Option<String>,
        authorization_details: Option<Vec<InitiateIssuanceAuthorizationDetailDTO>>,
        issuer_state: Option<String>,
        scope: Option<Vec<String>>,
        authorization_server: Option<String>,
    },
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIProofTypeSupported {
    pub proof_signing_alg_values_supported: Vec<String>,
    pub key_attestations_required: Option<OpenID4VCIKeyAttestationsRequired>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct OpenID4VCIKeyAttestationsRequired {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_storage: Vec<KeyStorageSecurityLevel>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub user_authentication: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, From, Into)]
#[from(KeyStorageSecurity)]
#[into(KeyStorageSecurity)]
pub enum KeyStorageSecurityLevel {
    #[serde(rename = "iso_18045_high")]
    High,
    #[serde(rename = "iso_18045_moderate")]
    Moderate,
    #[serde(rename = "iso_18045_enhanced-basic")]
    EnhancedBasic,
    #[serde(rename = "iso_18045_basic")]
    Basic,
}

impl KeyStorageSecurityLevel {
    pub fn select_lowest(levels: &[Self]) -> Option<Self> {
        levels
            .iter()
            .min_by_key(|level| match level {
                Self::High => 4,
                Self::Moderate => 3,
                Self::EnhancedBasic => 2,
                Self::Basic => 1,
            })
            .cloned()
    }
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

#[derive(Clone, Debug)]
pub(crate) struct UpdateResponse {
    pub result: SubmitIssuerResponse,
    pub create_did: Option<Did>,
    pub create_key: Option<Key>,
    pub create_certificate: Option<Certificate>,
    pub create_identifier: Option<Identifier>,
    pub create_credential: Option<Credential>,
    pub create_credential_schema: Option<CredentialSchema>,
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
pub(crate) struct ShareResponse {
    pub url: String,
    pub interaction_id: InteractionId,
    pub interaction_data: Option<Vec<u8>>,
    pub expires_at: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub(crate) struct ContinueIssuanceResponseDTO {
    pub interaction_id: InteractionId,
    pub key_storage_security_levels: Option<Vec<KeyStorageSecurity>>,
    pub key_algorithms: Option<Vec<String>>,
}
