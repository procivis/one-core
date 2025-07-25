use std::collections::HashMap;

use dcql::DcqlQuery;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    AuthorizationEncryptedResponseAlgorithm,
    AuthorizationEncryptedResponseContentEncryptionAlgorithm, ClientIdScheme,
    OpenID4VCPresentationHolderParams, OpenID4VCRedirectUriParams, OpenID4VPClientMetadata,
    OpenID4VPClientMetadataJwks, OpenID4VpPresentationFormat, default_presentation_url_scheme,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_request_uri: bool,

    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,

    pub holder: OpenID4VCPresentationHolderParams,
    pub verifier: PresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationVerifierParams {
    pub supported_client_id_schemes: Vec<ClientIdScheme>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub(crate) struct AuthorizationRequestQueryParams {
    /// with client_id_scheme prefix
    pub client_id: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub dcql_query: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct AuthorizationRequest {
    /// with client_id_scheme prefix
    pub client_id: String,

    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,

    #[serde(default)]
    pub response_type: Option<String>,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub response_uri: Option<Url>,

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub client_metadata: Option<OpenID4VPClientMetadata>,

    #[serde(default)]
    pub dcql_query: Option<DcqlQuery>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Default)]
pub struct OpenID4VPFinal1_0ClientMetadata {
    #[serde(default)]
    pub jwks: Option<OpenID4VPClientMetadataJwks>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    pub vp_formats_supported: HashMap<String, OpenID4VpPresentationFormat>,
    #[serde(default)]
    pub authorization_encrypted_response_alg: Option<AuthorizationEncryptedResponseAlgorithm>,
    #[serde(default)]
    pub encrypted_response_enc_values_supported:
        Option<Vec<AuthorizationEncryptedResponseContentEncryptionAlgorithm>>,
    #[serde(default)]
    pub id_token_ecrypted_response_enc: Option<String>,
    #[serde(default)]
    pub id_token_encrypted_response_alg: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subject_syntax_types_supported: Vec<String>,
}
