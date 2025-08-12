use ct_codecs::{Base64UrlSafeNoPadding, Encoder};
use one_core::service::key::dto::{
    KeyGenerateCSRRequestDTO, KeyGenerateCSRRequestProfile, KeyGenerateCSRRequestSubjectDTO,
    KeyGenerateCSRResponseDTO, KeyListItemResponseDTO, KeyRequestDTO, KeyResponseDTO,
};
use one_dto_mapper::{From, Into, TryFrom};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ExactColumn, ListQueryParamsRest};
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyRequestRestDTO {
    /// Specify the organization.
    pub organisation_id: Uuid,
    /// Choose which key algorithm to use to create the key pair. Check
    /// the `keyAlgorithm` object of the configuration for supported options
    /// and reference the configuration instance.
    #[schema(example = "EDDSA")]
    pub key_type: String,
    /// The parameters passed into the key algorithm.
    #[schema(value_type = Object)]
    pub key_params: serde_json::Value,
    /// Must be unique within the organization.
    pub name: String,
    /// Choose a key storage type. Check the `keyStorage`
    /// object of the configuration for supported options and reference the
    /// configuration instance.
    #[schema(example = "INTERNAL")]
    pub storage_type: String,
    /// The parameters passed into the storage type.
    #[schema(value_type = Object)]
    pub storage_params: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = KeyResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyResponseRestDTO {
    #[try_from(infallible)]
    pub id: Uuid,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
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
    #[try_from(infallible)]
    pub is_remote: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = KeyListItemResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyListItemResponseRestDTO {
    #[try_from(infallible)]
    pub id: Uuid,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(with_fn = "Base64UrlSafeNoPadding::encode_to_string")]
    pub public_key: String,
    #[try_from(infallible)]
    pub key_type: String,
    #[try_from(infallible)]
    pub storage_type: String,
    #[try_from(infallible)]
    pub is_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::key::SortableKeyColumn")]
pub(crate) enum SortableKeyColumnRestDTO {
    Name,
    CreatedDate,
    PublicKey,
    KeyType,
    StorageType,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyFilterQueryParamsRest {
    /// Specify the organization from which to retrieve keys.
    pub organisation_id: OrganisationId,
    /// Return all keys with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only keys using the specified algorithms.
    #[param(rename = "keyTypes[]", nullable = false, example = json!(["EDDSA"]))]
    pub key_types: Option<Vec<String>>,
    /// Return only keys using the specified storage types.
    /// Possible values come from your configuration.
    #[param(rename = "keyStorages[]", nullable = false)]
    pub key_storages: Option<Vec<String>>,
    /// Filter by specific UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<KeyId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    /// Return only keys being a remote.
    #[param(inline, nullable = false)]
    pub is_remote: Option<Boolean>,
    /// Return only keys which were created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only keys which were created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only keys which were last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only keys which were last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

pub(crate) type GetKeyQuery =
    ListQueryParamsRest<KeyFilterQueryParamsRest, SortableKeyColumnRestDTO>;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyGenerateCSRRequestRestDTO {
    pub profile: KeyGenerateCSRRequestProfileRest,
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestProfile)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum KeyGenerateCSRRequestProfileRest {
    Generic,
    Mdl,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(KeyGenerateCSRRequestSubjectDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyGenerateCSRRequestSubjectRestDTO {
    /// Two-letter country code.
    pub country_name: Option<String>,
    /// Common name to include in the CSR, typically the domain name of the organization.
    pub common_name: Option<String>,

    pub state_or_province_name: Option<String>,
    pub organisation_name: Option<String>,
    pub locality_name: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(KeyGenerateCSRResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct KeyGenerateCSRResponseRestDTO {
    pub content: String,
}
