use one_core::service::did::dto::{
    CreateDidRequestKeysDTO, DidListItemResponseDTO, DidPatchRequestDTO, DidResponseDTO,
    DidResponseKeysDTO,
};
use one_dto_mapper::{From, Into, TryFrom, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{DidId, DidValue, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

pub type GetDidQuery = ListQueryParamsRest<DidFilterQueryParamsRest, SortableDidColumnRestDTO>;

/// Whether a DID was locally created or is the DID of a remote wallet.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::did::DidType")]
#[into("one_core::model::did::DidType")]
pub enum DidType {
    Remote,
    Local,
}

/// DID details.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DidListItemResponseDTO)]
pub struct DidListItemResponseRestDTO {
    pub id: DidId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub did: DidValue,
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[serde(rename = "method")]
    pub did_method: String,
    pub deactivated: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryFrom)]
#[try_from(T = DidResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseRestDTO {
    #[try_from(infallible)]
    pub id: DidId,
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
    #[try_from(infallible, with_fn = "convert_inner")]
    pub organisation_id: Option<Uuid>,
    #[try_from(infallible)]
    pub did: DidValue,
    #[try_from(infallible)]
    #[serde(rename = "type")]
    pub did_type: DidType,
    #[try_from(infallible)]
    #[serde(rename = "method")]
    pub did_method: String,
    pub keys: DidResponseKeysRestDTO,
    #[try_from(infallible)]
    pub deactivated: bool,
}

/// The key, or keys, defining the verification relationships of the DID.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, TryFrom)]
#[try_from(T = DidResponseKeysDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct DidResponseKeysRestDTO {
    #[try_from(with_fn = try_convert_inner)]
    pub authentication: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub assertion_method: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub key_agreement: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub capability_invocation: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub capability_delegation: Vec<KeyListItemResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestRestDTO {
    /// The DID name must be unique within the organization.
    pub name: String,
    /// Specify the organization.
    pub organisation_id: OrganisationId,
    /// Choose a DID method to create the DID. Check the `did` object of the
    /// configuration for supported options and reference the configuration
    /// instance.
    #[schema(example = "WEB")]
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    /// The parameters passed into the DID method.
    #[schema(value_type = Object)]
    pub params: Option<serde_json::Value>,
}

/// Each DID has five verification relationships defining the verification
/// method used for different purposes. Related guide: [Keys object](/dids#keys-object)
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, Into)]
#[into(CreateDidRequestKeysDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateDidRequestKeysRestDTO {
    #[into(with_fn = convert_inner)]
    pub authentication: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub assertion_method: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub key_agreement: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub capability_invocation: Vec<KeyId>,
    #[into(with_fn = convert_inner)]
    pub capability_delegation: Vec<KeyId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::did::SortableDidColumn")]
pub enum SortableDidColumnRestDTO {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactDidFilterColumnRestEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into("one_core::model::did::KeyRole")]
pub enum KeyRoleRestEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
    UpdateKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct DidFilterQueryParamsRest {
    /// Return only DIDs with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return all DIDs with addresses starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub did: Option<String>,
    /// Filter by DIDs created locally or DIDs of remote wallets from credentials
    /// issued or proofs requested.
    #[param(nullable = false)]
    pub r#type: Option<DidType>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactDidFilterColumnRestEnum>>,
    pub organisation_id: OrganisationId,
    /// Filter by active or deactivated DIDs.
    #[param(inline, nullable = false)]
    pub deactivated: Option<Boolean>,
    /// Return only DIDs which support the key algorithms specified here. Uses values
    /// from the configuration.
    #[param(rename = "keyAlgorithms[]", nullable = false)]
    pub key_algorithms: Option<Vec<String>>,
    #[param(rename = "keyRoles[]", inline, nullable = false)]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    /// Return only DIDs whose keys use the specified key storage type. Check the
    /// `keyStorage` object of the configuration for supported options.
    #[param(rename = "keyStorages[]", nullable = false)]
    pub key_storages: Option<Vec<String>>,
    /// Return only DIDs which use the specified keys.
    #[param(rename = "keyIds[]", inline, nullable = false)]
    pub key_ids: Option<Vec<KeyId>>,
    /// Return only DIDs of the method(s) specified here. Check the `did` object
    /// of the configuration for supported options.
    #[param(rename = "didMethods[]", nullable = false)]
    pub did_methods: Option<Vec<String>>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(DidPatchRequestDTO)]
pub struct DidPatchRequestRestDTO {
    pub deactivated: Option<bool>,
}
