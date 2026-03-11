use one_core::model::trust_entry::{SortableTrustEntryColumn, TrustEntryStatusEnum};
use one_core::model::trust_list_publication::{
    SortableTrustListPublicationColumn, TrustListPublicationRoleEnum,
};
use one_core::service::error::ServiceError;
use one_core::service::trust_list_publication::dto::{
    CreateTrustEntryRequestDTO, CreateTrustListPublicationRequestDTO,
    GetTrustListPublicationResponseDTO, TrustEntryListItemResponseDTO,
    TrustListPublicationListItemResponseDTO, UpdateTrustEntryRequestDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, IdentifierId, KeyId, OrganisationId, TrustEntryId, TrustListPublicationId,
    TrustListPublisherId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, GetListResponseRestDTO, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateTrustListPublicationRequestDTO, Error = ServiceError)]
pub struct CreateTrustListRequestRestDTO {
    #[try_into(infallible)]
    pub r#type: String,
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub identifier_id: IdentifierId,
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_id: Option<KeyId>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub certificate_id: Option<CertificateId>,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub role: TrustListPublicationRoleRestEnum,
    #[try_into(infallible)]
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateTrustEntryRequestDTO)]
pub struct CreateTrustEntryRequestRestDTO {
    pub identifier_id: IdentifierId,
    pub params: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(UpdateTrustEntryRequestDTO)]
pub struct UpdateTrustEntryRequestRestDTO {
    #[into(with_fn = convert_inner)]
    pub status: Option<TrustEntryStatusRestEnum>,
    pub params: Option<serde_json::Value>,
}

pub(crate) type GetTrustListPublicationListResponseRestDTO =
    GetListResponseRestDTO<TrustListPublicationListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustListPublicationListItemResponseDTO)]
pub(crate) struct TrustListPublicationListItemResponseRestDTO {
    pub id: TrustListPublicationId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub r#type: TrustListPublisherId,
    pub role: TrustListPublicationRoleRestEnum,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deleted_at: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetTrustListPublicationResponseDTO)]
pub(crate) struct GetTrustListPublicationResponseRestDTO {
    pub id: TrustListPublicationId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub identifier: GetIdentifierListItemResponseRestDTO,
    pub r#type: TrustListPublisherId,
    pub role: TrustListPublicationRoleRestEnum,
    pub content: Option<serde_json::Value>,
    pub sequence_number: i64,
    pub metadata: serde_json::Value,
    pub organisation_id: OrganisationId,
}

pub(crate) type GetTrustEntryListResponseRestDTO =
    GetListResponseRestDTO<TrustEntryListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustEntryListItemResponseDTO)]
pub(crate) struct TrustEntryListItemResponseRestDTO {
    pub id: TrustEntryId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub status: TrustEntryStatusRestEnum,
    pub identifier: GetIdentifierListItemResponseRestDTO,
    pub params: serde_json::Value,
}

pub(crate) type ListTrustListPublicationsEntitiesQuery = ListQueryParamsRest<
    TrustListPublicationFilterQueryParamsRestDTO,
    SortableTrustListPublicationColumnRestEnum,
>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetTrustListQuery
pub(crate) struct TrustListPublicationFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<TrustListPublicationId>>,
    /// Return only trust lists with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter by one or more trust list types.
    #[param(rename = "types[]", nullable = false)]
    pub types: Option<Vec<String>>,
    /// Filter by one or more trust list roles.
    #[param(rename = "roles[]", nullable = false)]
    pub roles: Option<Vec<TrustListPublicationRoleRestEnum>>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    /// Return only trust lists created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust lists created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust lists last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust lists last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustListPublicationColumn)]
pub(crate) enum SortableTrustListPublicationColumnRestEnum {
    Role,
    Type,
    Name,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ExactTrustListFilterColumnRestEnum {
    Name,
}

pub(crate) type ListTrustEntryEntitiesQuery =
    ListQueryParamsRest<TrustEntryFilterQueryParamsRestDTO, SortableTrustEntryColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TrustEntryFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<TrustEntryId>>,
    /// Filter by one or more trust entry statuses.
    #[param(rename = "statuses[]", nullable = false)]
    pub statuses: Option<Vec<TrustEntryStatusRestEnum>>,
    /// Return only trust entries created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust entries created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust entries last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust entries last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustEntryColumn)]
pub(crate) enum SortableTrustEntryColumnRestEnum {
    Status,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ExactTrustEntryFilterColumnRestEnum {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[into(TrustEntryStatusEnum)]
#[from(TrustEntryStatusEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntryStatusRestEnum {
    Active,
    Suspended,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[into(TrustListPublicationRoleEnum)]
#[from(TrustListPublicationRoleEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustListPublicationRoleRestEnum {
    PidProvider,
    WalletProvider,
    WrpAcProvider,
    PubEeaProvider,
    QeaaProvider,
    QesrcProvider,
    WrpRcProvider,
    NationalRegistryRegistrar,
    Issuer,
    Verifier,
}
