use serde::{Deserialize, Serialize};
use shared_types::DidValue;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDTO {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    pub id: DidValue,
    pub verification_method: Vec<DidVerificationMethodDTO>,
    pub authentication: Option<Vec<String>>,
    pub assertion_method: Option<Vec<String>>,
    pub key_agreement: Option<Vec<String>>,
    pub capability_invocation: Option<Vec<String>>,
    pub capability_delegation: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidVerificationMethodDTO {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkDTO,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
pub enum PublicKeyJwkDTO {
    #[serde(rename = "EC")]
    Ec(PublicKeyJwkEllipticDataDTO),
    #[serde(rename = "RSA")]
    Rsa(PublicKeyJwkRsaDataDTO),
    #[serde(rename = "OKP")]
    Okp(PublicKeyJwkEllipticDataDTO),
    #[serde(rename = "oct")]
    Oct(PublicKeyJwkOctDataDTO),
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkRsaDataDTO {
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkOctDataDTO {
    k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticDataDTO {
    pub crv: String,
    #[serde(rename = "x")]
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
