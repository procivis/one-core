use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::OrganisationId;
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::serialize::{front_time, front_time_option};

#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateOrganisationRequestDTO)]
pub struct CreateOrganisationRequestRestDTO {
    #[into(with_fn = convert_inner)]
    pub id: Option<OrganisationId>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpsertOrganisationRequestRestDTO {
    #[schema(value_type = String, example = "My Organization")]
    pub name: Option<String>,
    #[schema(value_type = bool, example = true)]
    pub deactivate: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CreateOrganisationResponseRestDTO {
    pub id: OrganisationId,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetOrganisationDetailsResponseDTO)]
pub struct GetOrganisationDetailsResponseRestDTO {
    pub id: Uuid,
    pub name: String,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deactivated_at: Option<OffsetDateTime>,
}
