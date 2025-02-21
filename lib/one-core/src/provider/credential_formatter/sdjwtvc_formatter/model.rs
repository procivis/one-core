use std::collections::HashMap;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use serde_with::{serde_as, skip_serializing_none, DisplayFromStr};
use url::Url;

#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVc {
    #[serde(rename = "_sd", default, skip_serializing_if = "Vec::is_empty")]
    pub digests: Vec<String>,

    /// Hash algorithm
    /// https://www.iana.org/assignments/named-information/named-information.xhtml
    #[serde(rename = "_sd_alg", default)]
    pub hash_alg: Option<String>,

    #[serde(default, deserialize_with = "deserialize_status")]
    pub status: Option<SdJwtVcStatus>,

    #[serde(flatten)]
    pub public_claims: HashMap<String, Value>,
}

fn deserialize_status<'de, D>(deserializer: D) -> Result<Option<SdJwtVcStatus>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Status {
        SdJwt(SdJwtVcStatus),
        String(String),
    }

    let status: Option<Status> = Option::deserialize(deserializer)?;

    match status {
        Some(Status::SdJwt(status)) => Ok(Some(status)),
        // workaround for EUDI SD-JWT VC
        // see https://github.com/eu-digital-identity-wallet/eudi-srv-web-issuing-eudiw-py/issues/78 (point 4)
        Some(Status::String(s)) if s == "validation status URL" => Ok(None),
        Some(Status::String(s)) => Err(serde::de::Error::custom(format!(
            "Expected SdJwtVcStatus got a string: {s}"
        ))),
        None => Ok(None),
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcStatus {
    pub status_list: SdJwtVcStatusList,
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdJwtVcStatusList {
    #[serde_as(as = "DisplayFromStr")]
    #[serde(rename = "idx")]
    pub index: usize,
    pub uri: Url,
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use super::SdJwtVc;

    #[test]
    fn test_deserialize_sdjwt_vc_with_eudi_specific_status_list() {
        let c: SdJwtVc = serde_json::from_value(json!({
            "_sd": [],
            "status": "validation status URL"
        }))
        .unwrap();

        assert!(c.status.is_none());
    }

    #[test]
    fn test_fails_to_deserialize_sdjwt_vc_status_with_random_string() {
        let err = serde_json::from_value::<SdJwtVc>(json!({
            "_sd": [],
            "status": "abcd"
        }))
        .err()
        .unwrap();

        assert_eq!("Expected SdJwtVcStatus got a string: abcd", err.to_string());
    }
}
