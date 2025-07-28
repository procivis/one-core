use one_dto_mapper::{From, Into};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::common_mapper::secret_string;
use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::key::{
    Key, PrivateKeyJwk, PrivateKeyJwkEllipticData, PrivateKeyJwkMlweData, PublicKeyJwk,
    PublicKeyJwkEllipticData, PublicKeyJwkMlweData, PublicKeyJwkOctData, PublicKeyJwkRsaData,
    SortableKeyColumn,
};

pub struct KeyRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}

#[derive(Clone, Debug)]
pub struct KeyResponseDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
    pub is_remote: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, From)]
#[from(Key)]
pub struct KeyListItemResponseDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
}

pub type GetKeyListResponseDTO = GetListResponse<KeyListItemResponseDTO>;
pub type GetKeyQueryDTO = GetListQueryParams<SortableKeyColumn>;

#[derive(Debug)]
pub struct KeyGenerateCSRRequestDTO {
    pub profile: KeyGenerateCSRRequestProfile,
    pub subject: KeyGenerateCSRRequestSubjectDTO,
}

#[derive(Debug)]
pub enum KeyGenerateCSRRequestProfile {
    Generic,
    Mdl,
}

#[derive(Debug)]
pub struct KeyGenerateCSRRequestSubjectDTO {
    pub country_name: Option<String>,
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug)]
pub struct KeyGenerateCSRResponseDTO {
    pub content: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Into, From)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
#[into(PublicKeyJwk)]
#[from(PublicKeyJwk)]
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
            Self::Ec(val) => &val.r#use,
            Self::Rsa(val) => &val.r#use,
            Self::Okp(val) => &val.r#use,
            Self::Oct(val) => &val.r#use,
            Self::Mlwe(val) => &val.r#use,
        }
    }

    pub fn get_kid(&self) -> &Option<String> {
        match self {
            Self::Ec(val) => &val.kid,
            Self::Rsa(val) => &val.kid,
            Self::Okp(val) => &val.kid,
            Self::Oct(val) => &val.kid,
            Self::Mlwe(val) => &val.kid,
        }
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkRsaData)]
#[from(PublicKeyJwkRsaData)]
pub struct PublicKeyJwkRsaDataDTO {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkOctData)]
#[from(PublicKeyJwkOctData)]
pub struct PublicKeyJwkOctDataDTO {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkMlweData)]
#[from(PublicKeyJwkMlweData)]
pub struct PublicKeyJwkMlweDataDTO {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub x: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkEllipticData)]
#[from(PublicKeyJwkEllipticData)]
pub struct PublicKeyJwkEllipticDataDTO {
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default)]
    pub y: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Into, From)]
#[serde(rename_all = "camelCase")]
#[serde(tag = "kty")]
#[into(PrivateKeyJwk)]
#[from(PrivateKeyJwk)]
pub enum PrivateKeyJwkDTO {
    #[serde(rename = "EC")]
    Ec(PrivateKeyJwkEllipticDataDTO),
    #[serde(rename = "OKP")]
    Okp(PrivateKeyJwkEllipticDataDTO),
    #[serde(rename = "MLWE")]
    Mlwe(PrivateKeyJwkMlweDataDTO),
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, Into, From)]
#[into(PrivateKeyJwkMlweData)]
#[from(PrivateKeyJwkMlweData)]
pub struct PrivateKeyJwkMlweDataDTO {
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
    #[serde(with = "secret_string")]
    pub d: SecretString,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, Into, From)]
#[into(PrivateKeyJwkEllipticData)]
#[from(PrivateKeyJwkEllipticData)]
pub struct PrivateKeyJwkEllipticDataDTO {
    #[serde(default)]
    pub r#use: Option<String>,
    #[serde(default)]
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    #[serde(with = "secret_string")]
    pub d: SecretString,
}
