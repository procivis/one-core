use one_core::model::trust_collection::SortableTrustCollectionColumn;
use one_core::service::error::ServiceError;
use one_core::service::trust_collection::dto::{
    CreateTrustCollectionRequestDTO, GetTrustCollectionResponseDTO,
    TrustCollectionListItemResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{OrganisationId, TrustCollectionId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::{ExactColumn, GetListResponseRestDTO, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::front_time;

#[options_not_nullable]
#[derive(Debug, Deserialize, ToSchema, TryInto)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = CreateTrustCollectionRequestDTO, Error = ServiceError)]
pub struct CreateTrustCollectionRestDTO {
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    #[try_into(infallible)]
    pub name: String,
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
}

pub(crate) type ListTrustCollectionEntitiesQuery = ListQueryParamsRest<
    TrustCollectionFilterQueryParamsRestDTO,
    SortableTrustCollectionColumnRestEnum,
>;

#[derive(Clone, Debug, Deserialize, ToSchema, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetTrustCollectionListQuery
pub(crate) struct TrustCollectionFilterQueryParamsRestDTO {
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", nullable = false)]
    pub ids: Option<Vec<TrustCollectionId>>,
    /// Return only trust collections with a name starting with this string.
    /// Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
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
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only trust lists created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only trust lists last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only trust lists last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, with = "time::serde::rfc3339::option")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustCollectionColumn)]
pub(crate) enum SortableTrustCollectionColumnRestEnum {
    Name,
    LastModified,
    CreatedDate,
}
