use one_core::service::history::dto::HistoryResponseDTO;
use one_dto_mapper::{convert_inner, try_convert_inner, From, Into, TryFrom};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, EntityId, HistoryId, OrganisationId, ProofSchemaId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::dto::error::ErrorCode;
use crate::endpoint::credential::dto::GetCredentialResponseRestDTO;
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

pub type GetHistoryQuery =
    ListQueryParamsRest<HistoryFilterQueryParamsRest, SortableHistoryColumnRestDTO>;

#[skip_serializing_none]
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
}

#[skip_serializing_none]
#[derive(Serialize, ToSchema, TryFrom)]
#[try_from(T = HistoryResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub struct HistoryResponseDetailRestDTO {
    #[try_from(infallible)]
    pub id: HistoryId,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    pub action: HistoryAction,
    #[try_from(with_fn = convert_inner, infallible)]
    pub entity_id: Option<Uuid>,
    #[try_from(infallible)]
    pub entity_type: HistoryEntityType,
    #[try_from(infallible)]
    pub organisation_id: OrganisationId,
    #[try_from(with_fn = try_convert_inner)]
    pub metadata: Option<HistoryMetadataRestEnum>,
}

#[derive(Serialize, ToSchema, TryFrom)]
#[try_from(T = one_core::service::history::dto::HistoryMetadataResponse, Error = MapperError)]
pub enum HistoryMetadataRestEnum {
    UnexportableEntities(UnexportableEntitiesResponseRestDTO),
    ErrorMetadata(#[try_from(infallible)] HistoryErrorMetadataRestDTO),
}

#[derive(Debug, Clone, Serialize, ToSchema, TryFrom)]
#[try_from(T = one_core::service::backup::dto::UnexportableEntitiesResponseDTO, Error = MapperError)]
pub struct UnexportableEntitiesResponseRestDTO {
    #[try_from(with_fn = convert_inner, infallible)]
    pub credentials: Vec<GetCredentialResponseRestDTO>,
    #[try_from(with_fn = try_convert_inner)]
    pub keys: Vec<KeyListItemResponseRestDTO>,
    #[try_from(with_fn = convert_inner, infallible)]
    pub dids: Vec<DidListItemResponseRestDTO>,
    #[try_from(infallible)]
    pub total_credentials: u64,
    #[try_from(infallible)]
    pub total_keys: u64,
    #[try_from(infallible)]
    pub total_dids: u64,
}

#[derive(Serialize, ToSchema, From)]
#[from("one_core::service::history::dto::HistoryErrorMetadataDTO")]
pub struct HistoryErrorMetadataRestDTO {
    pub error_code: ErrorCode,
    pub message: String,
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
    Activated,
    Withdrawn,
    Removed,
    Retracted,
    Updated,
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
    /// Return only events associated with the specified entity type(s).
    #[param(rename = "entityTypes[]", inline, nullable = false)]
    pub entity_types: Option<Vec<HistoryEntityType>>,
    /// Return only events associated with the provided entity UUID.
    #[param(nullable = false)]
    pub entity_id: Option<EntityId>,
    /// Return only events of the specified action(s).
    #[param(nullable = false)]
    pub action: Option<HistoryAction>,
    /// Return only events which occurred after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String)]
    pub created_date_from: Option<OffsetDateTime>,
    /// Return only events which occurred before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(value_type = String)]
    pub created_date_to: Option<OffsetDateTime>,
    /// Return only events associated with the provided DID UUID.
    #[param(nullable = false)]
    pub did_id: Option<DidId>,
    /// Return only events associated with the provided credential UUID.
    #[param(nullable = false)]
    pub credential_id: Option<CredentialId>,
    /// Return only events associated with the provided credential schema UUID.
    #[param(nullable = false)]
    pub credential_schema_id: Option<CredentialSchemaId>,
    /// Return only events associated with the provided proof schema UUID.
    #[param(nullable = false)]
    pub proof_schema_id: Option<ProofSchemaId>,
    /// Search for a string.
    #[param(nullable = false)]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. If no value is provided, events
    /// that have any field matching `searchText` will be returned.
    #[param(nullable = false)]
    pub search_type: Option<HistorySearchEnumRest>,
    /// Specify the organizaton from which to return history events.
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
