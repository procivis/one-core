//! OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//!
//! Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)

use serde::Deserialize;
use url::Url;

pub const DPOP_HEADER: &str = "DPoP";
pub const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";
pub const DPOP_JWT_TYPE: &str = "dpop+jwt";

/// Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2)
#[derive(Clone, Debug, Deserialize)]
pub struct DPoPClaims {
    pub htm: String,
    pub htu: Url,
    pub ath: Option<String>,
    pub nonce: Option<String>,
}
