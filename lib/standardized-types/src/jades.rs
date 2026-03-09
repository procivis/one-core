//! JAdES — JSON Advanced Electronic Signatures
//!
//! Protected header for JAdES Baseline B-B compact JWS.
//! Spec: ETSI TS 119 182-1 V1.2.1

use serde::{Deserialize, Serialize};

/// JAdES Baseline B-B protected header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JadesHeader {
    pub alg: String,
    pub typ: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crit: Vec<String>,
    pub iat: i64,
    pub x5c: Vec<String>,
    #[serde(rename = "x5t#S256", default)]
    pub x5t_s256: Option<String>,
}
