use serde::{de::Error, Deserialize, Serialize};
use shared_types::DidValue;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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
    pub k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PublicKeyJwkMlweDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub alg: String,
    pub x: String,
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

#[derive(Debug, Clone)]
pub struct MinMax<const N: usize> {
    pub min: usize,
    pub max: usize,
}

impl<const N: usize> MinMax<N> {
    fn contains(&self, number: usize) -> bool {
        (&self.min..=&self.max).contains(&&number)
    }
}

impl<const N: usize> Default for MinMax<N> {
    fn default() -> Self {
        Self { min: 1, max: 1 }
    }
}

impl<'a, const N: usize> Deserialize<'a> for MinMax<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'a>,
    {
        #[derive(Deserialize)]
        struct Proxy {
            min: usize,
            max: usize,
        }

        let val = Proxy::deserialize(deserializer)?;

        if val.min < N {
            return Err(Error::custom(format!("`min` cannot be smaller then {N}")));
        }

        if val.max < val.min {
            return Err(Error::custom("`max` cannot be smaller then `min`"));
        }

        Ok(MinMax {
            min: val.min,
            max: val.max,
        })
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Keys {
    #[serde(default, flatten)]
    pub global: MinMax<1>,
    #[serde(default)]
    pub authentication: MinMax<0>,
    #[serde(default)]
    pub assertion_method: MinMax<0>,
    #[serde(default)]
    pub key_agreement: MinMax<0>,
    #[serde(default)]
    pub capability_invocation: MinMax<0>,
    #[serde(default)]
    pub capability_delegation: MinMax<0>,
}

impl Keys {
    pub fn validate_keys(&self, keys: AmountOfKeys) -> bool {
        self.global.contains(keys.global)
            && self.authentication.contains(keys.authentication)
            && self.assertion_method.contains(keys.assertion)
            && self.key_agreement.contains(keys.key_agreement)
            && self
                .capability_invocation
                .contains(keys.capability_invocation)
            && self
                .capability_delegation
                .contains(keys.capability_delegation)
    }
}

#[derive(Debug, Clone)]
pub struct AmountOfKeys {
    pub global: usize,
    pub authentication: usize,
    pub assertion: usize,
    pub key_agreement: usize,
    pub capability_invocation: usize,
    pub capability_delegation: usize,
}
