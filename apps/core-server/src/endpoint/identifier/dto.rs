use std::collections::HashMap;

use one_core::model::identifier::{IdentifierState, IdentifierType, SortableIdentifierColumn};
use one_core::service::certificate::dto::CreateCertificateRequestDTO;
use one_core::service::identifier::dto::{
    CreateIdentifierDidRequestDTO, CreateIdentifierRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use one_core::service::trust_entity::dto::{
    ResolveTrustEntitiesRequestDTO, ResolveTrustEntitiesResponseDTO, ResolveTrustEntityRequestDTO,
};
use one_dto_mapper::{
    From, Into, TryFrom, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::dto::common::ListQueryParamsRest;
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::did::dto::{CreateDidRequestKeysRestDTO, DidResponseRestDTO, KeyRoleRestEnum};
use crate::endpoint::key::dto::KeyResponseRestDTO;
use crate::endpoint::trust_entity::dto::GetTrustEntityResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[skip_serializing_none]
#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateIdentifierRequestDTO)]
pub struct CreateIdentifierRequestRestDTO {
    pub name: String,
    #[into(with_fn = "convert_inner")]
    pub did: Option<CreateIdentifierDidRequestRestDTO>,
    pub key_id: Option<KeyId>,
    #[into(with_fn = "convert_inner_of_inner")]
    pub certificates: Option<Vec<CreateCertificateRequestRestDTO>>,
    pub organisation_id: OrganisationId,
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateIdentifierDidRequestDTO)]
pub struct CreateIdentifierDidRequestRestDTO {
    pub name: Option<String>,
    /// Specify the DID method. Check the `did` object of your configuration
    /// for supported options.
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    pub params: Option<serde_json::Value>,
}

#[skip_serializing_none]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateCertificateRequestDTO)]
pub struct CreateCertificateRequestRestDTO {
    pub name: Option<String>,
    pub chain: String,
    pub key_id: KeyId,
}

#[skip_serializing_none]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListItemResponseDTO)]
pub struct GetIdentifierListItemResponseRestDTO {
    pub id: IdentifierId,
    pub name: String,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub state: IdentifierStateRest,
    pub r#type: IdentifierTypeRest,
    /// Whether the identifier belongs to the system or comes from an interaction
    /// with an external actor.
    pub is_remote: bool,
    pub organisation_id: Option<OrganisationId>,
}

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = GetIdentifierResponseDTO, Error = MapperError)]
pub struct GetIdentifierResponseRestDTO {
    #[try_from(infallible)]
    pub id: IdentifierId,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[try_from(with_fn = "try_convert_inner")]
    pub did: Option<DidResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner")]
    pub key: Option<KeyResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner_of_inner")]
    pub certificates: Option<Vec<CertificateResponseRestDTO>>,
    #[try_from(infallible, with_fn = "convert_inner")]
    pub organisation_id: Option<OrganisationId>,
    #[try_from(infallible)]
    pub state: IdentifierStateRest,
    #[try_from(infallible)]
    pub r#type: IdentifierTypeRest,
    #[try_from(infallible)]
    pub is_remote: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierState)]
#[into(IdentifierState)]
pub enum IdentifierStateRest {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierType)]
#[into(IdentifierType)]
pub enum IdentifierTypeRest {
    Did,
    Key,
    Certificate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableIdentifierColumn)]
#[into(SortableIdentifierColumn)]
pub enum SortableIdentifierColumnRest {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct IdentifierFilterQueryParamsRestDTO {
    /// Specify identifiers to return by their UUID.
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<IdentifierId>>,
    /// Return only identifiers with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only identifiers of a certain type.
    #[param(rename = "types[]", nullable = false)]
    pub types: Option<Vec<IdentifierTypeRest>>,
    /// Return only active or deactivated identifiers.
    #[param(nullable = false)]
    pub state: Option<IdentifierStateRest>,
    #[param(rename = "didMethods[]", nullable = false)]
    pub did_methods: Option<Vec<String>>,
    /// If true, return only identifiers from interactions with external
    /// actors. If false, return only identifiers local to the system.
    #[param(nullable = false)]
    #[serde(default, deserialize_with = "deserialize_bool_from_string")]
    pub is_remote: Option<bool>,
    /// Return keys or DIDs whose keys use the specified algorithm. Check the
    /// `keyAlgorithm` object of the configuration for supported options.
    #[param(rename = "keyAlgorithms[]", nullable = false)]
    pub key_algorithms: Option<Vec<String>>,
    #[param(rename = "keyRoles[]", inline, nullable = false)]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    /// Return keys or DIDs whose keys use the specified storage type. Check the
    /// `keyStorage` object of the configuration for supported options.
    #[param(rename = "keyStorages[]", nullable = false)]
    pub key_storages: Option<Vec<String>>,

    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactIdentifierFilterColumnRestEnum>>,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactIdentifierFilterColumnRestEnum {
    Name,
}

pub type GetIdentifierQuery =
    ListQueryParamsRest<IdentifierFilterQueryParamsRestDTO, SortableIdentifierColumnRest>;

#[skip_serializing_none]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListResponseDTO)]
pub struct GetIdentifierListResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = "convert_inner")]
    pub values: Vec<GetIdentifierListItemResponseRestDTO>,
}

#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase")]
#[into(ResolveTrustEntitiesRequestDTO)]
pub struct ResolveTrustEntitiesRequestRestDTO {
    #[into(with_fn = "convert_inner")]
    pub identifiers: Vec<ResolveTrustEntityRequestRestDTO>,
}

#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase")]
#[into(ResolveTrustEntityRequestDTO)]
pub struct ResolveTrustEntityRequestRestDTO {
    pub id: IdentifierId,
    pub certificate_id: Option<CertificateId>,
}

#[derive(Debug, Serialize, ToSchema, Validate, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolveTrustEntitiesResponseDTO)]
pub struct ResolveTrustEntitiesResponseRestDTO {
    #[serde(flatten)]
    #[from(with_fn = "convert_inner")]
    pub identifier_to_trust_entity: HashMap<IdentifierId, GetTrustEntityResponseRestDTO>,
}

fn deserialize_bool_from_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => match s.to_lowercase().as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Err(serde::de::Error::custom("invalid boolean value")),
        },
        None => Ok(None),
    }
}
