use serde::{Deserialize, Serialize};
use shared_types::DidValue;

use crate::service::key::dto::PublicKeyJwkDTO;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDTO {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,
    pub id: DidValue,
    pub verification_method: Vec<DidVerificationMethodDTO>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<String>>,
    #[serde(flatten)]
    pub rest: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidVerificationMethodDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkDTO,
}
