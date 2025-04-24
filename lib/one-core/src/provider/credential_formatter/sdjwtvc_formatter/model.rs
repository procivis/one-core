use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_with::{serde_as, skip_serializing_none};
use url::Url;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVc {
    #[serde(rename = "vct")]
    pub vc_type: String,

    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default)]
    pub hash_alg: Option<String>,

    #[serde(default)]
    pub status: Option<SdJwtVcStatus>,

    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SdJwtVcStatus {
    pub status_list: SdJwtVcStatusList,
    #[serde(flatten)]
    pub custom_claims: HashMap<String, Value>,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcStatusList {
    #[serde(rename = "idx", deserialize_with = "deserialize_string_or_number")]
    pub index: usize,
    pub uri: Url,
}

fn deserialize_string_or_number<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let v = Value::deserialize(deserializer)?;

    match v {
        Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        Value::Number(n) => n
            .as_u64()
            .map(|n| n as usize)
            .ok_or(serde::de::Error::custom(
                "failed to deserialize status list index",
            )),
        _ => Err(serde::de::Error::custom(
            "failed to deserialize status list index",
        )),
    }
}
