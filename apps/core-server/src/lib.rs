use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub mod dto;
pub mod endpoint;
pub mod extractor;
pub mod mapper;
pub mod metrics;
pub mod router;
pub mod serialize;

pub mod build_info {
    use shadow_rs::shadow;

    shadow!(build);

    pub use build::*;
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
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
}
