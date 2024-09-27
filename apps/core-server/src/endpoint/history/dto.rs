use one_core::service::history::dto::HistoryResponseDTO;
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, EntityId, HistoryId, OrganisationId, ProofSchemaId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::mapper::convert_history_metadata;
use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::serialize::front_time;

pub type GetHistoryQuery =
    ListQueryParamsRest<HistoryFilterQueryParamsRest, SortableHistoryColumnRestDTO>;

#[derive(Debug, Clone, Deserialize, Serialize, ToSchema)]
pub enum HistoryMetadataRest {
    // dummy entry just to make ToSchema compile
    Nothing,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(HistoryResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponseRestDTO {
    pub id: HistoryId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    #[from(with_fn = convert_inner)]
    pub entity_id: Option<Uuid>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: OrganisationId,
    #[from(with_fn = convert_history_metadata)]
    pub metadata: Option<HistoryMetadataRest>,
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
    Errored,
    Issued,
    Offered,
    Reactivated,
    Rejected,
    Requested,
    Revoked,
    Pending,
    Suspended,
    Restored,
    Shared,
    Imported,
    ClaimsRemoved,
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
    Backup,
    TrustAnchor,
    TrustEntity,
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
    #[param(inline, rename = "entityTypes[]")]
    pub entity_types: Option<Vec<HistoryEntityType>>,
    pub entity_id: Option<EntityId>,
    pub action: Option<HistoryAction>,
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date_from: Option<OffsetDateTime>,
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date_to: Option<OffsetDateTime>,
    pub did_id: Option<DidId>,
    pub credential_id: Option<CredentialId>,
    pub credential_schema_id: Option<CredentialSchemaId>,
    pub proof_schema_id: Option<ProofSchemaId>,
    pub search_text: Option<String>,
    pub search_type: Option<HistorySearchEnumRest>,
    pub organisation_id: OrganisationId,
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
    ProofSchemaName,
}
