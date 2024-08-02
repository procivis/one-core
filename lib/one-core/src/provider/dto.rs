use dto_mapper::{convert_inner, From, Into};
use one_providers::common_models::did::DidValue;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::PublicKeyJwk)]
#[into(one_providers::common_models::PublicKeyJwk)]
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
    #[serde(rename = "MLWE")]
    Mlwe(PublicKeyJwkMlweDataDTO),
}

impl PublicKeyJwkDTO {
    pub fn get_use(&self) -> &Option<String> {
        match self {
            PublicKeyJwkDTO::Ec(val) => &val.r#use,
            PublicKeyJwkDTO::Rsa(val) => &val.r#use,
            PublicKeyJwkDTO::Okp(val) => &val.r#use,
            PublicKeyJwkDTO::Oct(val) => &val.r#use,
            PublicKeyJwkDTO::Mlwe(val) => &val.r#use,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::PublicKeyJwkRsaData)]
#[into(one_providers::common_models::PublicKeyJwkRsaData)]
pub struct PublicKeyJwkRsaDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::PublicKeyJwkOctData)]
#[into(one_providers::common_models::PublicKeyJwkOctData)]
pub struct PublicKeyJwkOctDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::PublicKeyJwkMlweData)]
#[into(one_providers::common_models::PublicKeyJwkMlweData)]
pub struct PublicKeyJwkMlweDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, From, Into)]
#[from(one_providers::common_models::PublicKeyJwkEllipticData)]
#[into(one_providers::common_models::PublicKeyJwkEllipticData)]
pub struct PublicKeyJwkEllipticDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Into)]
#[from(one_providers::did::model::DidDocument)]
#[into(one_providers::did::model::DidDocument)]
pub struct DidDocumentDTO {
    pub context: serde_json::Value,
    pub id: DidValue,
    #[from(with_fn = "convert_inner")]
    #[into(with_fn = "convert_inner")]
    pub verification_method: Vec<DidVerificationMethod>,
    pub authentication: Option<Vec<String>>,
    pub assertion_method: Option<Vec<String>>,
    pub key_agreement: Option<Vec<String>>,
    pub capability_invocation: Option<Vec<String>>,
    pub capability_delegation: Option<Vec<String>>,

    pub rest: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize, From, Into)]
#[from(one_providers::did::model::DidVerificationMethod)]
#[into(one_providers::did::model::DidVerificationMethod)]
pub struct DidVerificationMethod {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    pub public_key_jwk: PublicKeyJwkDTO,
}
