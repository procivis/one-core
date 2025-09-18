use one_core::service::organisation::dto::{
    CreateOrganisationRequestDTO, GetOrganisationDetailsResponseDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{IdentifierId, OrganisationId};
use time::OffsetDateTime;
use utoipa::ToSchema;
use uuid::Uuid;

use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CreateOrganisationRequestDTO)]
pub(crate) struct CreateOrganisationRequestRestDTO {
    #[into(with_fn = convert_inner)]
    pub id: Option<OrganisationId>,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UpsertOrganisationRequestRestDTO {
    #[schema(value_type = String, example = "My Organization")]
    pub name: Option<String>,
    #[schema(value_type = bool, example = true)]
    pub deactivate: Option<bool>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub wallet_provider: Option<Option<String>>,
    #[serde(default, with = "::serde_with::rust::double_option")]
    pub wallet_provider_issuer: Option<Option<IdentifierId>>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateOrganisationResponseRestDTO {
    pub id: OrganisationId,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(GetOrganisationDetailsResponseDTO)]
pub(crate) struct GetOrganisationDetailsResponseRestDTO {
    pub id: Uuid,
    pub name: String,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    #[serde(serialize_with = "front_time_option")]
    pub deactivated_at: Option<OffsetDateTime>,
    pub wallet_provider: Option<String>,
    #[from(with_fn = convert_inner)]
    pub wallet_provider_issuer: Option<GetIdentifierListItemResponseRestDTO>,
}
