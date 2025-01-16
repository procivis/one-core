use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::OrganisationId;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::key::{
    Key, PublicKeyJwk, PublicKeyJwkEllipticData, PublicKeyJwkMlweData, PublicKeyJwkOctData,
    PublicKeyJwkRsaData, SortableKeyColumn,
};

pub struct KeyRequestDTO {
    pub organisation_id: OrganisationId,
    pub key_type: String,
    pub key_params: serde_json::Value,
    pub name: String,
    pub storage_type: String,
    pub storage_params: serde_json::Value,
}

pub struct KeyResponseDTO {
    pub id: Uuid,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub name: String,
    pub public_key: Vec<u8>,
    pub key_type: String,
    pub storage_type: String,
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
    Mdl,
}

#[derive(Debug)]
pub struct KeyGenerateCSRRequestSubjectDTO {
    pub country_name: String,
    pub common_name: String,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug)]
pub struct KeyGenerateCSRResponseDTO {
    pub content: String,
}

#[derive(Debug)]
pub struct KeyCheckCertificateRequestDTO {
    pub certificate: String,
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkRsaData)]
#[from(PublicKeyJwkRsaData)]
pub struct PublicKeyJwkRsaDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkOctData)]
#[from(PublicKeyJwkOctData)]
pub struct PublicKeyJwkOctDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub k: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkMlweData)]
#[from(PublicKeyJwkMlweData)]
pub struct PublicKeyJwkMlweDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq, Into, From)]
#[into(PublicKeyJwkEllipticData)]
#[from(PublicKeyJwkEllipticData)]
pub struct PublicKeyJwkEllipticDataDTO {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#use: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}
