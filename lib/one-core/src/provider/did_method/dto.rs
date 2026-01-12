use serde::{Deserialize, Serialize};
use serde_with::{OneOrMany, serde_as, skip_serializing_none};
use shared_types::DidValue;
use standardized_types::jwk::PublicJwk;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDTO {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,
    pub id: DidValue,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DidVerificationMethodDTO>,
    #[serde(default)]
    pub authentication: Option<Vec<String>>,
    #[serde(default)]
    pub assertion_method: Option<Vec<String>>,
    #[serde(default)]
    pub key_agreement: Option<Vec<String>>,
    #[serde(default)]
    pub capability_invocation: Option<Vec<String>>,
    #[serde(default)]
    pub capability_delegation: Option<Vec<String>>,
    #[serde(default)]
    pub also_known_as: Option<Vec<String>>,
    #[serde(default)]
    pub service: Option<Vec<DidServiceEndointDTO>>,
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidServiceEndointDTO {
    pub id: String,
    #[serde_as(as = "OneOrMany<_>")]
    pub r#type: Vec<String>,
    pub service_endpoint: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidVerificationMethodDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicJwk,
}
