use std::collections::HashMap;

use one_core::model::identifier::{IdentifierState, IdentifierType, SortableIdentifierColumn};
use one_core::service::certificate::dto::CreateCertificateRequestDTO;
use one_core::service::error::ServiceError;
use one_core::service::identifier::dto::{
    CreateCertificateAuthorityRequestDTO, CreateIdentifierDidRequestDTO,
    CreateIdentifierKeyRequestDTO, CreateIdentifierRequestDTO,
    CreateSelfSignedCertificateAuthorityRequestDTO, GetIdentifierListItemResponseDTO,
    GetIdentifierListResponseDTO, GetIdentifierResponseDTO,
};
use one_core::service::trust_entity::dto::{
    ResolveTrustEntitiesRequestDTO, ResolveTrustEntitiesResponseDTO, ResolveTrustEntityRequestDTO,
    ResolvedIdentifierTrustEntityResponseDTO,
};
use one_dto_mapper::{
    From, Into, TryFrom, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
    try_convert_inner_of_inner,
};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use validator::Validate;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::did::dto::{CreateDidRequestKeysRestDTO, DidResponseRestDTO, KeyRoleRestEnum};
use crate::endpoint::key::dto::{KeyGenerateCSRRequestSubjectRestDTO, KeyResponseRestDTO};
use crate::endpoint::trust_entity::dto::GetTrustEntityResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Validate, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateIdentifierRequestDTO, Error = ServiceError)]
pub(crate) struct CreateIdentifierRequestRestDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub did: Option<CreateIdentifierDidRequestRestDTO>,
    #[try_into(infallible)]
    #[schema(deprecated = true)]
    /// Deprecated. Use the `key` field instead.
    #[schema(deprecated = true)]
    pub key_id: Option<KeyId>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub key: Option<CreateIdentifierKeyRequestRestDTO>,
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificates: Option<Vec<CreateCertificateRequestRestDTO>>,
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    pub certificate_authorities: Option<Vec<CreateCertificateAuthorityRequestRestDTO>>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateIdentifierDidRequestDTO)]
pub(crate) struct CreateIdentifierDidRequestRestDTO {
    pub name: Option<String>,
    /// Specify the DID method. Check the `did` object of your configuration
    /// for supported options.
    #[modify_schema(field = did)]
    pub method: String,
    pub keys: CreateDidRequestKeysRestDTO,
    pub params: Option<serde_json::Value>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateRequestDTO)]
pub(crate) struct CreateCertificateRequestRestDTO {
    pub name: Option<String>,
    pub chain: String,
    pub key_id: KeyId,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateIdentifierKeyRequestDTO)]
pub(crate) struct CreateIdentifierKeyRequestRestDTO {
    pub key_id: KeyId,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateCertificateAuthorityRequestDTO)]
pub(crate) struct CreateCertificateAuthorityRequestRestDTO {
    pub key_id: KeyId,
    pub name: Option<String>,
    pub chain: Option<String>,
    #[into(with_fn = convert_inner)]
    pub self_signed: Option<CreateSelfSignedCertificateAuthorityRequestRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateSelfSignedCertificateAuthorityRequestDTO)]
pub(crate) struct CreateSelfSignedCertificateAuthorityRequestRestDTO {
    pub content: CreateCaCSRRequestRestDTO,
    #[modify_schema(field = signer)]
    pub signer: String,
    pub validity_start: Option<OffsetDateTime>,
    pub validity_end: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateCaCSRRequestRestDTO {
    pub subject: KeyGenerateCSRRequestSubjectRestDTO,
}

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListItemResponseDTO)]
pub(crate) struct GetIdentifierListItemResponseRestDTO {
    pub id: IdentifierId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub state: IdentifierStateRest,
    pub r#type: IdentifierTypeRest,
    /// Whether the identifier belongs to the system or comes from an interaction
    /// with an external actor.
    pub is_remote: bool,
    pub organisation_id: Option<OrganisationId>,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[serde(rename_all = "camelCase")]
#[try_from(T = GetIdentifierResponseDTO, Error = MapperError)]
pub(crate) struct GetIdentifierResponseRestDTO {
    #[try_from(infallible)]
    pub id: IdentifierId,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(infallible)]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[try_from(with_fn = "try_convert_inner")]
    pub did: Option<DidResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner")]
    pub key: Option<KeyResponseRestDTO>,
    #[try_from(with_fn = "try_convert_inner_of_inner")]
    pub certificates: Option<Vec<CertificateResponseRestDTO>>,
    #[try_from(with_fn = "try_convert_inner_of_inner")]
    pub certificate_authorities: Option<Vec<CertificateResponseRestDTO>>,
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
pub(crate) enum IdentifierStateRest {
    Active,
    Deactivated,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(IdentifierType)]
#[into(IdentifierType)]
pub(crate) enum IdentifierTypeRest {
    Did,
    Key,
    Certificate,
    #[serde(rename = "CA")]
    CertificateAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableIdentifierColumn)]
#[into(SortableIdentifierColumn)]
pub(crate) enum SortableIdentifierColumnRest {
    Name,
    CreatedDate,
    Type,
    State,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetIdentifierQuery
pub(crate) struct IdentifierFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<IdentifierId>>,
    /// Return only identifiers with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter by one or more identifier types.
    #[param(rename = "types[]", nullable = false)]
    pub types: Option<Vec<IdentifierTypeRest>>,
    /// Filter by one or more identifier states.
    #[param(rename = "states[]", nullable = false)]
    pub states: Option<Vec<IdentifierStateRest>>,
    /// Filter by one or more DID methods.
    #[param(rename = "didMethods[]", nullable = false)]
    pub did_methods: Option<Vec<String>>,
    /// If true, return only identifiers from interactions with external
    /// actors. If false, return only identifiers local to the system.
    #[param(inline, nullable = false)]
    pub is_remote: Option<Boolean>,
    /// Return keys or DIDs whose keys use the specified algorithm. Check the
    /// `keyAlgorithm` object of the configuration for supported options.
    #[param(rename = "keyAlgorithms[]", nullable = false)]
    pub key_algorithms: Option<Vec<String>>,
    /// Return keys used as one or more verification methods of a DID.
    #[param(rename = "keyRoles[]", inline, nullable = false)]
    pub key_roles: Option<Vec<KeyRoleRestEnum>>,
    /// Return keys or DIDs whose keys use the specified storage type. Check the
    /// `keyStorage` object of the configuration for supported options.
    #[param(rename = "keyStorages[]", nullable = false)]
    pub key_storages: Option<Vec<String>>,

    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactIdentifierFilterColumnRestEnum>>,
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,

    /// Return only identifiers created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only identifiers created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only identifiers last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only identifiers last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ExactIdentifierFilterColumnRestEnum {
    Name,
}

pub(crate) type GetIdentifierQuery =
    ListQueryParamsRest<IdentifierFilterQueryParamsRestDTO, SortableIdentifierColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetIdentifierListResponseDTO)]
pub(crate) struct GetIdentifierListResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = "convert_inner")]
    pub values: Vec<GetIdentifierListItemResponseRestDTO>,
}

#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(ResolveTrustEntitiesRequestDTO)]
pub(crate) struct ResolveTrustEntitiesRequestRestDTO {
    #[into(with_fn = "convert_inner")]
    pub identifiers: Vec<ResolveTrustEntityRequestRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Validate, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(ResolveTrustEntityRequestDTO)]
pub(crate) struct ResolveTrustEntityRequestRestDTO {
    pub id: IdentifierId,
    pub certificate_id: Option<CertificateId>,
}

#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolveTrustEntitiesResponseDTO)]
pub(crate) struct ResolveTrustEntitiesResponseRestDTO {
    #[serde(flatten)]
    #[from(with_fn = "convert_inner_of_inner")]
    pub identifier_to_trust_entity:
        HashMap<IdentifierId, Vec<ResolvedIdentifierTrustEntityResponseRestDTO>>,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(ResolvedIdentifierTrustEntityResponseDTO)]
pub(crate) struct ResolvedIdentifierTrustEntityResponseRestDTO {
    #[serde(flatten)]
    pub trust_entity: GetTrustEntityResponseRestDTO,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificate_ids: Vec<CertificateId>,
}
