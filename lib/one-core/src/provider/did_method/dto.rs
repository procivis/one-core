use serde::{Deserialize, Serialize};
use shared_types::DidValue;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DidDocumentDTO {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
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

impl PublicKeyJwkDTO {
    pub fn get_use(&self) -> &Option<String> {
        match self {
            PublicKeyJwkDTO::Ec(val) => &val.r#use,
            PublicKeyJwkDTO::Rsa(val) => &val.r#use,
            PublicKeyJwkDTO::Okp(val) => &val.r#use,
            PublicKeyJwkDTO::Oct(val) => &val.r#use,
        }
    }
}

pub const ENC: &str = "enc";
pub const SIG: &str = "sig";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkRsaDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkOctDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkEllipticDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
