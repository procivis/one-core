use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::service::key::dto::{
    KeyCheckCertificateRequestDTO, KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile,
    KeyGenerateCSRRequestSubjectDTO, KeyGenerateCSRResponseDTO, KeyListItemResponseDTO,
    KeyRequestDTO, KeyResponseDTO,
};
use one_dto_mapper::{From, Into, TryFrom};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::dto::common::GetListQueryParams;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(KeyRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestRestDTO {
    pub organisation_id: Uuid,
    #[schema(example = "EDDSA")]
    pub key_type: String,
    #[schema(value_type = Object)]
    pub key_params: serde_json::Value,
    pub name: String,
    #[schema(example = "INTERNAL")]
    pub storage_type: String,
    #[schema(value_type = Object)]
    pub storage_params: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryFrom)]
#[try_from(T = KeyResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct KeyResponseRestDTO {
    #[try_from(infallible)]
    pub id: Uuid,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub organisation_id: Uuid,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(with_fn = "Base64UrlSafeNoPadding::encode_to_string")]
    pub public_key: String,
    #[try_from(infallible)]
    pub key_type: String,
    #[try_from(infallible)]
    pub storage_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryFrom)]
#[try_from(T = KeyListItemResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct KeyListItemResponseRestDTO {
    #[try_from(infallible)]
    pub id: Uuid,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(with_fn = "Base64UrlSafeNoPadding::encode_to_string")]
    pub public_key: String,
    #[try_from(infallible)]
    pub key_type: String,
    #[try_from(infallible)]
    pub storage_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::key::SortableKeyColumn")]
pub enum SortableKeyColumnRestDTO {
    Name,
    CreatedDate,
    PublicKey,
    KeyType,
    StorageType,
}

pub type GetKeyQuery = GetListQueryParams<SortableKeyColumnRestDTO>;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerateCSRRequestRestDTO {
    pub profile: KeyGenerateCSRRequestProfileRest,
    #[serde(rename = "nbf", with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub not_before: OffsetDateTime,
    #[serde(rename = "exp", with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub expires_at: OffsetDateTime,
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestProfile)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyGenerateCSRRequestProfileRest {
    Mdl,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestSubjectDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerateCSRRequestSubjectRestDTO {
    pub country_name: String,
    pub common_name: String,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(KeyGenerateCSRResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerateCSRResponseRestDTO {
    pub content: String,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyCheckCertificateRequestDTO)]
pub struct KeyCheckCertificateRequestRestDTO {
    pub certificate: String,
}
