use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDJWTVCVc {
    #[serde(rename = "_sd")]
    pub disclosures: Vec<String>,

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default, skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,

    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}
