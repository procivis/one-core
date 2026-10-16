//! OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//!
//! Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html)

use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use url::Url;

pub const DPOP_HEADER: &str = "DPoP";
pub const DPOP_NONCE_HEADER: &str = "DPoP-Nonce";
pub const DPOP_JWT_TYPE: &str = "dpop+jwt";

/// Spec: [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2)
#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DPoPClaims {
    pub htm: String,
    pub htu: Url,
    pub ath: Option<String>,
    pub nonce: Option<String>,
}
