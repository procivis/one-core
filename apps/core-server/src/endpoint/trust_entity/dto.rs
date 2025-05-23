use one_core::model::trust_entity::{TrustEntityRole, TrustEntityState};
use one_core::service::error::ServiceError;
use one_core::service::trust_entity::dto::{
    CreateRemoteTrustEntityRequestDTO, GetTrustEntityResponseDTO, SortableTrustEntityColumnEnum,
    TrustEntitiesResponseItemDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{DidId, OrganisationId, TrustAnchorId, TrustEntityId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::trust_anchor::dto::{
    GetTrustAnchorDetailResponseRestDTO, GetTrustAnchorResponseRestDTO,
};
use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustEntityRequestRestDTO {
    /// Specify the entity name.
    pub(super) name: String,
    /// base64 encoded image. Maximum size = 50kb.
    pub(super) logo: Option<String>,
    /// Specify the entity's domain name.
    pub(super) website: Option<String>,
    /// Specify a Terms of Service URL.
    pub(super) terms_url: Option<String>,
    /// Specify the Privacy Policy URL.
    pub(super) privacy_url: Option<String>,
    /// Whether the entity is a trusted issuer, verifier, or both.
    pub(super) role: TrustEntityRoleRest,
    /// Specify trust anchor ID.
    pub(super) trust_anchor_id: TrustAnchorId,
    /// Specify DID ID.
    pub(super) did_id: DidId,
}

/// Whether the trust entity issues credentials, verifies credentials, or both.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[into(TrustEntityRole)]
#[from(TrustEntityRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityRoleRest {
    Issuer,
    Verifier,
    Both,
}

/// Trust entity state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[into(TrustEntityState)]
#[from(TrustEntityState)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TrustEntityStateRest {
    Active,
    Removed,
    Withdrawn,
    RemovedAndWithdrawn,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(GetTrustEntityResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustEntityResponseRestDTO {
    pub id: TrustEntityId,
    pub organisation_id: Option<OrganisationId>,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub trust_anchor: GetTrustAnchorDetailResponseRestDTO,
    pub did: DidListItemResponseRestDTO,
    pub state: TrustEntityStateRest,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustEntityColumnEnum)]
pub enum SortableTrustEntityColumnRestEnum {
    Name,
    Role,
    LastModified,
    State,
}

pub type ListTrustEntitiesQuery =
    ListQueryParamsRest<TrustEntityFilterQueryParamsRestDto, SortableTrustEntityColumnRestEnum>;

#[derive(Clone, Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct TrustEntityFilterQueryParamsRestDto {
    #[param(nullable = false)]
    pub name: Option<String>,
    #[param(nullable = false)]
    pub role: Option<TrustEntityRoleRest>,
    #[param(nullable = false)]
    pub trust_anchor_id: Option<TrustAnchorId>,
    #[param(nullable = false)]
    pub did_id: Option<DidId>,
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    pub organisation_id: Option<OrganisationId>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustEntitiesResponseItemDTO)]
pub struct ListTrustEntitiesResponseItemRestDTO {
    pub id: TrustEntityId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub logo: Option<String>,
    pub website: Option<String>,
    pub terms_url: Option<String>,
    pub state: TrustEntityStateRest,
    pub privacy_url: Option<String>,
    pub role: TrustEntityRoleRest,
    pub trust_anchor: GetTrustAnchorResponseRestDTO,
    pub did: DidListItemResponseRestDTO,
}

#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T = CreateRemoteTrustEntityRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct CreateRemoteTrustEntityRequestRestDTO {
    /// Specify trust anchor ID.
    #[serde(default)]
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub trust_anchor_id: Option<TrustAnchorId>,
    /// Specify local DID.
    #[try_into(infallible)]
    pub did_id: DidId,
    /// Specify the entity name.
    #[try_into(infallible)]
    pub name: String,
    /// base64 encoded image. Maximum size = 50kb.
    #[schema(nullable = false)]
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<String>,
    /// Specify the entity's domain name.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub website: Option<String>,
    /// Specify a Terms of Service URL.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub terms_url: Option<String>,
    /// Specify the Privacy Policy URL.
    #[schema(nullable = false)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub privacy_url: Option<String>,
    #[try_into(infallible)]
    pub role: TrustEntityRoleRest,
}
