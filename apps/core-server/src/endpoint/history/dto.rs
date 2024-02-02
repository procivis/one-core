use dto_mapper::{From, Into};
use serde::{Deserialize, Deserializer, Serialize};
use shared_types::{DidId, EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use one_core::service::history::dto::HistoryResponseDTO;

use crate::{dto::common::ListQueryParamsRest, serialize::front_time};

pub type GetHistoryQuery =
    ListQueryParamsRest<HistoryFilterQueryParamsRest, SortableHistoryColumnRestDTO>;

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(HistoryResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponseRestDTO {
    pub id: HistoryId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub entity_id: Uuid,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::history::HistoryAction")]
#[into("one_core::model::history::HistoryAction")]
pub enum HistoryAction {
    Accepted,
    Created,
    Deactivated,
    Deleted,
    Issued,
    Offered,
    Rejected,
    Requested,
    Revoked,
    Pending,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::history::HistoryEntityType")]
#[into("one_core::model::history::HistoryEntityType")]
pub enum HistoryEntityType {
    Key,
    Did,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::history::SortableHistoryColumn")]
pub enum SortableHistoryColumnRestDTO {
    CreatedDate,
    Action,
    EntityType,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct HistoryFilterQueryParamsRest {
    pub entity_type: Option<HistoryEntityType>,
    pub entity_id: Option<EntityId>,
    pub action: Option<HistoryAction>,
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date_from: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date_to: Option<OffsetDateTime>,
    pub did_id: Option<DidId>,
    pub credential_id: Option<Uuid>,
    pub credential_schema_id: Option<Uuid>,
    pub search_text: Option<String>,
    pub search_type: Option<HistorySearchEnumRest>,
    pub organisation_id: OrganisationId,
}

fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<Option<OffsetDateTime>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Some(time::serde::rfc3339::deserialize(deserializer)?))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into)]
#[into("one_core::model::history::HistorySearchEnum")]
#[serde(rename_all = "camelCase")]
pub enum HistorySearchEnumRest {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
    IssuerDid,
    IssuerName,
    VerifierDid,
    VerifierName,
}
