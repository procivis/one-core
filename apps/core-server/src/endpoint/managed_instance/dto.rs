use one_core::model::instance::{InstanceRole, InstanceStatus};
use one_core::model::managed_instance::{ManagedInstanceOs, SortableManagedInstanceColumn};
use one_core::service::error::ServiceError;
use one_core::service::managed_instance::dto;
use one_core::service::managed_instance::dto::ManagedInstanceFilterParamsDTO;
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{ManagedInstanceId, OrganisationId};
use standardized_types::jwk::PublicJwk;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::{front_time, front_time_option};

pub(crate) type ListManagedInstancesQuery =
    ListQueryParamsRest<ManagedInstanceFilterQueryParamsRestDTO, SortableManagedInstanceColumnRest>;

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetManagedInstanceListResponseDTO)]
pub(crate) struct GetManagedInstancesResponseRestDTO {
    pub total_pages: u64,
    pub total_items: u64,
    #[from(with_fn = convert_inner)]
    pub values: Vec<ManagedInstanceResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(dto::GetManagedInstanceResponseDTO)]
pub(crate) struct ManagedInstanceResponseRestDTO {
    pub id: ManagedInstanceId,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub created_date: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time")]
    pub last_modified: OffsetDateTime,
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub last_issuance: Option<OffsetDateTime>,
    pub name: String,
    pub os: ManagedInstanceOsRestEnum,
    pub status: InstanceStatusRestEnum,
    pub role: InstanceRoleRestEnum,
    pub provider_name: String,
    pub provider_type: String,
    #[from(with_fn = convert_inner)]
    pub authentication_key_jwk: Option<PublicJwk>,
    pub user_sub: Option<String>,
    pub verifier_csr: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(ManagedInstanceOs)]
#[into(ManagedInstanceOs)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ManagedInstanceOsRestEnum {
    Ios,
    Android,
    Web,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(InstanceStatus)]
#[into(InstanceStatus)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum InstanceStatusRestEnum {
    Active,
    Revoked,
    Pending,
    Unattested,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, ToSchema, From, Into)]
#[from(InstanceRole)]
#[into(InstanceRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum InstanceRoleRestEnum {
    Wallet,
    Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = ManagedInstanceFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside ListManagedInstancesQuery
pub(crate) struct ManagedInstanceFilterQueryParamsRestDTO {
    /// Return only instances with a name starting with this string.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by specific instance UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<ManagedInstanceId>>,
    /// Return only instances with the specified status.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<InstanceStatusRestEnum>>,
    /// Return only instances with the specified operating systems.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "os[]", inline, nullable = false)]
    pub os: Option<Vec<ManagedInstanceOsRestEnum>>,
    /// Return only instances with the specified providers.
    #[param(rename = "providerNames[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub provider_names: Option<Vec<String>>,
    /// Filter by instance role.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "roles[]", inline, nullable = false)]
    pub roles: Option<Vec<InstanceRoleRestEnum>>,
    /// Return only the instances with the specified attestation.
    #[param(rename = "attestation", inline, nullable = false)]
    #[try_into(infallible)]
    pub attestation: Option<String>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only instances created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only instances created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only instances with a userSub starting with this string.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub user_sub: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From, Into)]
#[serde(rename_all = "camelCase")]
#[from(SortableManagedInstanceColumn)]
#[into(SortableManagedInstanceColumn)]
pub(crate) enum SortableManagedInstanceColumnRest {
    CreatedDate,
    LastModified,
    Name,
    Status,
    Os,
    UserSub,
}
