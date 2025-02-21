use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::DidValue;

use crate::service::key::dto::PublicKeyJwkDTO;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDTO {
    #[serde(rename = "@context")]
    pub context: serde_json::Value,
    pub id: DidValue,
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
