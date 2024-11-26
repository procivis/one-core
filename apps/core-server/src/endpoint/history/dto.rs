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
    #[param(rename = "entityTypes[]", inline, nullable = false)]
    pub entity_types: Option<Vec<HistoryEntityType>>,
    #[param(nullable = false)]
    pub entity_id: Option<EntityId>,
    #[param(nullable = false)]
    pub action: Option<HistoryAction>,
    /// timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z')
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String)]
    pub created_date_from: Option<OffsetDateTime>,
    /// timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z')
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String)]
    pub created_date_to: Option<OffsetDateTime>,
    #[param(nullable = false)]
    pub did_id: Option<DidId>,
    #[param(nullable = false)]
    pub credential_id: Option<CredentialId>,
    #[param(nullable = false)]
    pub credential_schema_id: Option<CredentialSchemaId>,
    #[param(nullable = false)]
    pub proof_schema_id: Option<ProofSchemaId>,
    #[param(nullable = false)]
    pub search_text: Option<String>,
    #[param(nullable = false)]
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
