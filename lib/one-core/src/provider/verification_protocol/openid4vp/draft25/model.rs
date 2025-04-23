use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

use crate::provider::verification_protocol::openid4vp::mapper::deserialize_with_serde_json;
use crate::provider::verification_protocol::openid4vp::model::{
    default_presentation_url_scheme, OpenID4VCPresentationHolderParams,
    OpenID4VCPresentationVerifierParams, OpenID4VCRedirectUriParams, OpenID4VPClientMetadata,
    OpenID4VPPresentationDefinition,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OpenID4Vp25Params {
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_request_uri: bool,

    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,
    #[serde(default)]
    pub x509_ca_certificate: Option<String>,
    pub holder: OpenID4VCPresentationHolderParams,
    pub verifier: OpenID4VCPresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct OpenID4VP25AuthorizationRequestQueryParams {
    pub client_id: String,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub client_metadata: Option<String>,
    pub presentation_definition: Option<String>,
    pub presentation_definition_uri: Option<String>,

    // https://www.rfc-editor.org/rfc/rfc9101.html#name-authorization-request
    pub request: Option<String>,
    pub request_uri: Option<String>,

    pub redirect_uri: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Deserialize, Serialize, Debug, Default)]
pub(crate) struct OpenID4VP25AuthorizationRequest {
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

    #[serde(default, deserialize_with = "deserialize_with_serde_json")]
    pub presentation_definition: Option<OpenID4VPPresentationDefinition>,

    #[serde(default)]
    pub presentation_definition_uri: Option<Url>,

    #[serde(default)]
    pub redirect_uri: Option<String>,
}
