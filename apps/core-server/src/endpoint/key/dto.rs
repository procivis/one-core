use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile, KeyGenerateCSRRequestSubjectDTO,
    KeyGenerateCSRResponseDTO, KeyListItemResponseDTO, KeyRequestDTO, KeyResponseDTO,
};
use one_dto_mapper::{From, Into, TryFrom};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(KeyRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyRequestRestDTO {
    /// Specify the organization.
    pub organisation_id: Uuid,
    /// Choose which key algorithm to use to create the key pair. Check
    /// the `keyAlgorithm` object of the configuration for supported options
    /// and reference the configuration instance.
    #[schema(example = "EDDSA")]
    pub key_type: String,
    /// The parameters passed into the key algorithm.
    #[schema(value_type = Option<Object>)]
    pub key_params: serde_json::Value,
    /// Must be unique within the organization.
    pub name: String,
    /// Choose a key storage type. Check the `keyStorage`
    /// object of the configuration for supported options and reference the
    /// configuration instance.
    #[schema(example = "INTERNAL")]
    pub storage_type: String,
    /// The parameters passed into the storage type.
    #[schema(value_type = Option<Object>)]
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct KeyFilterQueryParamsRest {
    /// Specify the organization from which to retrieve keys.
    pub organisation_id: OrganisationId,
    /// Return all keys with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only keys of the specified algorithm.
    #[param(nullable = false)]
    pub key_type: Option<String>,
    /// Return only keys stored in the specified storage type.
    #[param(nullable = false)]
    pub key_storage: Option<String>,
    /// Specify keys to return by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<KeyId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
}

pub type GetKeyQuery = ListQueryParamsRest<KeyFilterQueryParamsRest, SortableKeyColumnRestDTO>;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerateCSRRequestRestDTO {
    pub profile: KeyGenerateCSRRequestProfileRest,
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestProfile)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyGenerateCSRRequestProfileRest {
    Generic,
    Mdl,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestSubjectDTO)]
#[serde(rename_all = "camelCase")]
pub struct KeyGenerateCSRRequestSubjectRestDTO {
    /// Two-letter country code.
    pub country_name: Option<String>,
    /// Common name to include in the CSR, typically the domain name of the organization.
    pub common_name: Option<String>,

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
