//! Spec https://datatracker.ietf.org/doc/html/rfc7517

use secrecy::SecretString;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use serde_with::skip_serializing_none;
use sha2::{Digest, Sha256};
use strum::Display;

use crate::mapper::secret_string;

#[derive(Clone, Serialize, Deserialize, Debug, Default, PartialEq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct Jwks {
    pub keys: Vec<PublicJwk>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
pub enum PublicJwk {
    #[serde(rename = "EC")]
    Ec(PublicJwkEc),
    #[serde(rename = "RSA")]
    Rsa(PublicJwkRsa),
    #[serde(rename = "OKP")]
    Okp(PublicJwkEc),
    #[serde(rename = "oct")]
    Oct(PublicJwkOct),
    /// Specified in https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-11.html
    #[serde(rename = "AKP")]
    Akp(PublicJwkAkp),
}

impl PublicJwk {
    pub fn alg(&self) -> Option<&str> {
        match self {
            PublicJwk::Ec(ec) | PublicJwk::Okp(ec) => ec.alg.as_deref(),
            PublicJwk::Rsa(rsa) => rsa.alg.as_deref(),
            PublicJwk::Oct(oct) => oct.alg.as_deref(),
            PublicJwk::Akp(akp) => Some(&akp.alg),
        }
    }
    pub fn r#use(&self) -> Option<&JwkUse> {
        match self {
            Self::Ec(val) => val.r#use.as_ref(),
            Self::Rsa(val) => val.r#use.as_ref(),
            Self::Okp(val) => val.r#use.as_ref(),
            Self::Oct(val) => val.r#use.as_ref(),
            Self::Akp(val) => val.r#use.as_ref(),
        }
    }

    pub fn kid(&self) -> Option<&str> {
        match self {
            Self::Ec(val) => val.kid.as_deref(),
            Self::Rsa(val) => val.kid.as_deref(),
            Self::Okp(val) => val.kid.as_deref(),
            Self::Oct(val) => val.kid.as_deref(),
            Self::Akp(val) => val.kid.as_deref(),
        }
    }

    pub fn set_kid(&mut self, key_id: String) {
        match self {
            Self::Ec(val) => val.kid = Some(key_id),
            Self::Rsa(val) => val.kid = Some(key_id),
            Self::Okp(val) => val.kid = Some(key_id),
            Self::Oct(val) => val.kid = Some(key_id),
            Self::Akp(val) => val.kid = Some(key_id),
        }
    }

    /// SHA-256 JWK thumbprint, <https://www.rfc-editor.org/rfc/rfc7638.html>
    pub fn thumbprint(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut serializer = serde_json::Serializer::new(Vec::new());
        let mut map = serializer.serialize_map(None)?;
        match self {
            Self::Ec(params) => {
                map.serialize_entry("crv", &params.crv)?;
                map.serialize_entry("kty", "EC")?;
                map.serialize_entry("x", &params.x)?;
                map.serialize_entry("y", &params.y)?;
            }
            Self::Rsa(params) => {
                map.serialize_entry("e", &params.e)?;
                map.serialize_entry("kty", "RSA")?;
                map.serialize_entry("n", &params.n)?;
            }
            Self::Okp(params) => {
                map.serialize_entry("crv", &params.crv)?;
                map.serialize_entry("kty", "OKP")?;
                map.serialize_entry("x", &params.x)?;
            }
            Self::Oct(params) => {
                map.serialize_entry("k", &params.k)?;
                map.serialize_entry("kty", "oct")?;
            }
            Self::Akp(params) => {
                map.serialize_entry("alg", &params.alg)?;
                map.serialize_entry("kty", "AKP")?;
                map.serialize_entry("pub", &params.r#pub)?;
            }
        };
        map.end()?;
        Ok(Sha256::digest(serializer.into_inner()).to_vec())
    }
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PublicJwkRsa {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PublicJwkOct {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PublicJwkAkp {
    pub alg: String,
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub r#pub: String,
}

#[skip_serializing_none]
#[cfg_attr(feature = "utoipa", proc_macros::options_not_nullable)]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct PublicJwkEc {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
pub enum PrivateJwk {
    #[serde(rename = "EC")]
    Ec(PrivateJwkEc),
    #[serde(rename = "OKP")]
    Okp(PrivateJwkEc),
    /// Specified in https://www.ietf.org/archive/id/draft-ietf-cose-dilithium-11.html
    #[serde(rename = "AKP")]
    Akp(PrivateJwkAkp),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateJwkAkp {
    pub alg: String,
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub r#pub: String,
    #[serde(with = "secret_string")]
    pub r#priv: SecretString,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateJwkEc {
    #[serde(default)]
    pub r#use: Option<JwkUse>,
    #[serde(default)]
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    #[serde(with = "secret_string")]
    pub d: SecretString,
}

/// see: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>
#[derive(Clone, Debug, Display, Eq, PartialEq, Deserialize, Serialize)]
pub enum JwkUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
    #[serde(untagged)]
    Unknown(String),
}

#[cfg(feature = "utoipa")]
mod utoipa_schema {
    use utoipa::openapi::{ObjectBuilder, RefOr, Schema, Type};
    use utoipa::{PartialSchema, ToSchema};

    use super::JwkUse;

    impl PartialSchema for JwkUse {
        fn schema() -> RefOr<Schema> {
            RefOr::T(Schema::Object(
                ObjectBuilder::new()
                    .schema_type(Type::String)
                    .description(Some(
                        "see: <https://datatracker.ietf.org/doc/html/rfc7517#section-4.2>",
                    ))
                    .examples(["sig", "enc"])
                    .build(),
            ))
        }
    }

    impl ToSchema for JwkUse {}
}

impl From<String> for JwkUse {
    fn from(value: String) -> Self {
        match value.as_str() {
            "sig" => Self::Signature,
            "enc" => Self::Encryption,
            _ => Self::Unknown(value),
        }
    }
}
