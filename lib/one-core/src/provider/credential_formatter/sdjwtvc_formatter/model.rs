use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, DisplayFromStr};
use url::Url;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDJWTVCVc {
    #[serde(rename = "_sd")]
    pub disclosures: Vec<String>,

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default, skip_serializing_if = "Option::is_none")]
    pub hash_alg: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<SDJWTVCStatus>,

    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDJWTVCStatus {
    pub status_list: SDJWTVCStatusList,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SDJWTVCStatusList {
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "idx")]
    pub index: usize,
    pub uri: Url,
}
