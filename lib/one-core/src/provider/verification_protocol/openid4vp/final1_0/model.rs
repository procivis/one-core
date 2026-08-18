use std::collections::HashMap;

use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use standardized_types::openid4vp::{ClientIdPrefix, PresentationFormat};
use time::Duration;

use crate::provider::verification_protocol::model::CommonParams;
use crate::provider::verification_protocol::openid4vp::model::{
    OpenID4VCRedirectUriParams, default_presentation_url_scheme,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Params {
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub use_legacy_did_client_id_scheme: bool,
    #[serde(default)]
    pub use_request_uri: bool,

    #[serde(default = "default_presentation_url_scheme")]
    pub url_scheme: String,

    pub holder: HolderParams,
    pub verifier: PresentationVerifierParams,
    pub redirect_uri: OpenID4VCRedirectUriParams,
    /// According to https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-new-parameters
    /// `vp_formats_supported` can be omitted if known to the wallet by other means.
    /// One option for other means is to statically define it for an ecosystem (i.e. swiyu), which
    /// is why this option is supported here.
    pub predefined_vp_formats_supported: Option<HashMap<String, PresentationFormat>>,

    #[serde(flatten)]
    pub common: CommonParams,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HolderParams {
    pub supported_client_id_schemes: Vec<ClientIdPrefix>,
}

#[serde_as]
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PresentationVerifierParams {
    pub supported_client_id_schemes: Vec<ClientIdPrefix>,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    pub interaction_expires_in_seconds: Option<Duration>,
}
