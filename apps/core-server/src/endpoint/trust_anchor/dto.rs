use one_core::service::trust_anchor::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorDetailResponseDTO, SortableTrustAnchorColumn,
    TrustAnchorsListItemResponseDTO,
};
use one_dto_mapper::{From, Into};
use serde::{Deserialize, Serialize};
use shared_types::TrustAnchorId;
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::serialize::front_time;

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateTrustAnchorRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateTrustAnchorRequestRestDTO {
    /// Must be unique
    pub name: String,
    /// Specify the type of trust management anchor to publish or subscribe
    /// to. Possible values from the configuration.
    pub r#type: String,
    /// If true the created trust anchor will be published. If subscribing
    /// to an existing trust anchor, omit or set to false. The remote anchor has
    /// to be specified via `publisherReference`.
    #[schema(nullable = false)]
    pub is_publisher: Option<bool>,
    /// URL of the remote trust anchor to subscribe to.
    /// It must be provided if and only if `isPublisher=false`.
    #[schema(nullable = false)]
    pub publisher_reference: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[from(GetTrustAnchorDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorResponseRestDTO {
    pub id: TrustAnchorId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(TrustAnchorsListItemResponseDTO)]
pub struct ListTrustAnchorsResponseItemRestDTO {
    pub id: TrustAnchorId,
    pub name: String,

    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
    pub entities: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum ExactTrustAnchorFilterColumnRestEnum {
    Name,
    Type,
}

#[derive(Clone, Debug, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct TrustAnchorsFilterQueryParamsRest {
    #[param(nullable = false)]
    pub name: Option<String>,
    #[param(inline, nullable = false)]
    pub is_publisher: Option<Boolean>,
    #[param(nullable = false)]
    pub r#type: Option<String>,
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactTrustAnchorFilterColumnRestEnum>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableTrustAnchorColumn)]
pub enum SortableTrustAnchorColumnRestEnum {
    Name,
    CreatedDate,
    Type,
}

pub type ListTrustAnchorsQuery =
    ListQueryParamsRest<TrustAnchorsFilterQueryParamsRest, SortableTrustAnchorColumnRestEnum>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, ToSchema, From, Into)]
#[from(GetTrustAnchorDetailResponseDTO)]
#[into(GetTrustAnchorDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct GetTrustAnchorDetailResponseRestDTO {
    pub id: TrustAnchorId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub r#type: String,
    pub is_publisher: bool,
    pub publisher_reference: String,
}
