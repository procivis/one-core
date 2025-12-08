use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod deserialize;
pub mod dto;
pub mod endpoint;
pub mod extractor;
pub mod init;
pub mod mapper;
pub mod metrics;
pub mod openapi;
pub mod router;
pub mod serialize;
pub mod build_info {
    use shadow_rs::shadow;

    shadow!(build);

    pub use build::*;
}
mod authentication;
mod middleware;
mod permissions;
mod session;
mod sts_token_validator;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ServerConfig {
    #[serde(default)]
    pub database_url: String,
    #[serde(default)]
    pub server_ip: Option<IpAddr>,
    #[serde(default)]
    pub server_port: Option<u16>,
    #[serde(default)]
    pub trace_json: Option<bool>,
    #[serde(default)]
    pub core_base_url: String,
    #[serde(default)]
    pub sentry_dsn: Option<String>,
    #[serde(default)]
    pub sentry_environment: Option<String>,
    #[serde(default)]
    pub trace_level: Option<String>,
    // when set to true hides the `cause` field in the error response
    #[serde(default)]
    pub hide_error_response_cause: bool,
    #[serde(default)]
    pub allow_insecure_http_transport: bool,
    #[serde(default)]
    pub insecure_vc_api_endpoints_enabled: bool,
    /// whether endpoint metrics are available
    #[serde(default)]
    pub enable_metrics: bool,
    /// whether build-info and health endpoints are available
    #[serde(default)]
    pub enable_server_info: bool,
    /// whether swagger and openapi endpoints are available
    #[serde(default)]
    pub enable_open_api: bool,
    #[serde(default)]
    pub enable_external_endpoints: bool,
    #[serde(default)]
    pub enable_management_endpoints: bool,
    #[serde(default)]
    pub enable_wallet_provider: bool,
    #[serde(default)]
    pub enable_history_create_endpoint: bool,
    pub auth: AuthMode,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "mode", rename_all_fields = "camelCase")]
pub enum AuthMode {
    #[serde(rename = "UNSAFE_NONE")]
    UnsafeNone,
    #[serde(rename = "UNSAFE_STATIC")]
    UnsafeStatic { static_token: String },
    #[serde(rename = "STS")]
    SecurityTokenService {
        sts_token_validation: StsTokenValidation,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StsTokenValidation {
    aud: String,
    iss: String,
    jwks_uri: String,
    ttl_jwks: u64,
    leeway: u64,
}
