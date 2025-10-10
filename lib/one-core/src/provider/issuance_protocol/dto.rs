use serde::{Deserialize, Serialize};

use crate::config::core_config::DidType;

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
