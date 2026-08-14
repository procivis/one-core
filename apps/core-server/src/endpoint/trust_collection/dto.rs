use one_core::model::trust_collection::{
    ExactTrustCollectionFilterColumn, SortableTrustCollectionColumn,
};
use one_core::model::trust_list_role::TrustListRoleEnum;
use one_core::model::trust_list_subscription::{
    SortableTrustListSubscriptionColumn, TrustListSubscriptionState,
};
use one_core::proto::trust_collection::EUDI_ECOSYSTEM;
use one_core::service::error::ServiceError;
use one_core::service::trust_collection::dto::{
    CreateTrustCollectionRequestDTO, CreateTrustListSubscriptionRequestDTO,
    GetTrustCollectionResponseDTO, TrustCollectionFilterParamsDTO,
    TrustCollectionListItemResponseDTO, TrustListSubscriptionExactColumn,
    TrustListSubscriptionFilterParamsDTO, TrustListSubscriptionListItemResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    EcosystemId, OrganisationId, TrustCollectionId, TrustListSubscriberId, TrustListSubscriptionId,
};
use time::OffsetDateTime;
use url::Url;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::{Boolean, GetListResponseRestDTO, ListQueryParamsRest};
use crate::dto::default_true;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateTrustCollectionRequestDTO, Error = ServiceError)]
pub struct CreateTrustCollectionRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS mode
    /// this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Provide a name for this collection.
    #[try_into(infallible)]
    pub name: String,

    #[modify_schema(field = ecosystem)]
    #[try_into(infallible)]
    // TODO (ONE-9981): temporarily auto-fill EUDI if missing in the request
    #[serde(default = "eudi_ecosystem")]
    pub ecosystem: String,
}

fn eudi_ecosystem() -> String {
    EUDI_ECOSYSTEM.to_string()
}

pub(crate) type GetTrustCollectionListResponseRestDTO =
    GetListResponseRestDTO<TrustCollectionListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustCollectionListItemResponseDTO)]
pub(crate) struct TrustCollectionListItemResponseRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub remote_trust_collection_url: Option<Url>,
    pub ecosystem: EcosystemId,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetTrustCollectionResponseDTO)]
pub(crate) struct GetTrustCollectionResponseRestDTO {
    pub id: TrustCollectionId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    pub organisation_id: OrganisationId,
    pub remote_trust_collection_url: Option<Url>,
    pub ecosystem: EcosystemId,
}

pub(crate) type ListTrustCollectionEntitiesQuery = ListQueryParamsRest<
    TrustCollectionFilterQueryParamsRestDTO,
    SortableTrustCollectionColumnRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ExactTrustCollectionFilterColumn)]
pub(crate) enum ExactTrustCollectionFilterColumnRestEnum {
    Name,
}

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams, TryInto)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetTrustCollectionListQuery
#[try_into(T = TrustCollectionFilterParamsDTO, Error = ServiceError)]
pub(crate) struct TrustCollectionFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<TrustCollectionId>>,
    /// Return only trust collections with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub exact: Option<Vec<ExactTrustCollectionFilterColumnRestEnum>>,

    #[param(rename = "ecosystems[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ecosystems: Option<Vec<EcosystemId>>,

    /// Return only trust lists created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust lists created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust lists last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust lists last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// If true, include trust collections from the parent organization.
    /// If false, return only this organization's own trust collections.
    #[serde(default = "default_true")]
    #[try_into(infallible)]
    pub include_parent_organisation_collections: Boolean,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustCollectionColumn)]
pub(crate) enum SortableTrustCollectionColumnRestEnum {
    Name,
    LastModified,
    CreatedDate,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CreateTrustListSubscriptionRequestDTO)]
pub struct CreateTrustListSubscriptionRequestRestDTO {
    /// Provide a name for this subscription.
    pub name: String,
    /// For Lists of Trusted Entities (ETSI LoTE) only.
    /// Specify which ecosystem role this list corresponds to.
    #[into(with_fn = convert_inner)]
    pub role: Option<TrustListRoleRestEnum>,
    /// Provide the reference URL for the trust list.
    pub reference: Url,
    /// The configured `trustListSubscriber` instance the trust list
    /// conforms to.
    #[modify_schema(field = trust_list_subscriber)]
    pub r#type: String,
}

pub(crate) type GetTrustListSubscriptionListResponseRestDTO =
    GetListResponseRestDTO<TrustListSubscriptionListItemResponseRestDTO>;

#[options_not_nullable]
#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustListSubscriptionListItemResponseDTO)]
pub(crate) struct TrustListSubscriptionListItemResponseRestDTO {
    pub id: TrustListSubscriptionId,
    pub name: String,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[from(with_fn = convert_inner)]
    pub role: Option<TrustListRoleRestEnum>,
    pub reference: String,
    pub r#type: TrustListSubscriberId,
    pub state: TrustListSubscriptionStateRestEnum,
}

pub(crate) type ListTrustListSubscriptionsEntitiesQuery = ListQueryParamsRest<
    TrustListSubscriptionFilterQueryParamsRestDTO,
    SortableListTrustListSubscriptionColumnRestEnum,
>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams, TryInto)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetTrustCollectionListQuery
#[try_into(T = TrustListSubscriptionFilterParamsDTO, Error = ServiceError)]
pub(crate) struct TrustListSubscriptionFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<TrustListSubscriptionId>>,
    /// Return only trust list subscriptions with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Return only trust list subscriptions with a reference starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub reference: Option<String>,
    #[param(rename = "roles[]", nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub roles: Option<Vec<TrustListRoleRestEnum>>,
    #[param(rename = "states[]", nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub states: Option<Vec<TrustListSubscriptionStateRestEnum>>,
    #[param(rename = "types[]", nullable = false)]
    #[try_into(infallible)]
    pub types: Option<Vec<TrustListSubscriberId>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    pub exact: Option<Vec<TrustListSubscriptionExactColumnRestEnum>>,
    /// Return only trust lists created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust lists created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust lists last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust lists last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustListSubscriptionColumn)]
pub(crate) enum SortableListTrustListSubscriptionColumnRestEnum {
    Name,
    Reference,
    Role,
    Type,
    LastModified,
    CreatedDate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(TrustListSubscriptionExactColumn)]
pub(crate) enum TrustListSubscriptionExactColumnRestEnum {
    Name,
    Reference,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(TrustListSubscriptionState)]
#[from(TrustListSubscriptionState)]
pub enum TrustListSubscriptionStateRestEnum {
    Active,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Into, From, Deserialize, Serialize, ToSchema)]
#[into(TrustListRoleEnum)]
#[from(TrustListRoleEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustListRoleRestEnum {
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
