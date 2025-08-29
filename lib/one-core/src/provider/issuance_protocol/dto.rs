use serde::{Deserialize, Serialize};
use shared_types::DidValue;
use time::OffsetDateTime;

use crate::config::core_config::DidType;
use crate::model::credential_schema::{CredentialSchemaType, WalletStorageTypeEnum};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ConnectVerifierResponseRestDTO`
pub(crate) struct ConnectVerifierResponse {
    pub claims: Vec<ProofClaimSchema>,
    pub verifier_did: DidValue,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `ProofRequestClaimRestDTO`
pub(crate) struct ProofClaimSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub credential_schema: ProofCredentialSchema,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
/// deserializes matching `CredentialSchemaListValueResponseRestDTO`
pub(crate) struct ProofCredentialSchema {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_type: CredentialSchemaType,
    pub schema_id: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IssuanceProtocolCapabilities {
    pub features: Vec<Features>,
    pub did_methods: Vec<DidType>,
}

#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum Features {
    SupportsRejection,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ContinueIssuanceDTO {
    pub credential_issuer: String,
    pub authorization_code: String,
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Vec<String>,
    pub credential_configuration_ids: Vec<String>,
    pub code_verifier: Option<String>,
    pub authorization_server: Option<String>,
}
