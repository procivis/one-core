use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod deserialize;
pub mod did_config;
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
mod middleware;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(default, rename_all = "camelCase")]
pub struct ServerConfig {
    pub database_url: String,
    pub server_ip: Option<IpAddr>,
    pub server_port: Option<u16>,
    pub trace_json: Option<bool>,
    pub auth_token: String,
    pub core_base_url: String,
    pub sentry_dsn: Option<String>,
    pub sentry_environment: Option<String>,
    pub trace_level: Option<String>,
    // when set to true hides the `cause` field in the error response
    pub hide_error_response_cause: bool,
    pub allow_insecure_http_transport: bool,
    pub insecure_vc_api_endpoints_enabled: bool,
    /// whether endpoint metrics are available
    pub enable_metrics: bool,
    /// whether build-info and health endpoints are available
    pub enable_server_info: bool,
    /// whether swagger and openapi endpoints are available
    pub enable_open_api: bool,
    pub enable_external_endpoints: bool,
    pub enable_management_endpoints: bool,
}
