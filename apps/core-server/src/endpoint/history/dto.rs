use one_core::service::history::dto::{
    CreateHistoryRequestDTO, HistoryErrorMetadataDTO, HistoryResponseDTO,
};
use one_dto_mapper::{From, Into, TryFrom, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId,
    ProofSchemaId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::endpoint::credential::dto::{
    CredentialDetailClaimResponseRestDTO, GetCredentialResponseRestDTO,
};
use crate::endpoint::did::dto::DidListItemResponseRestDTO;
use crate::endpoint::key::dto::KeyListItemResponseRestDTO;
use crate::mapper::MapperError;
use crate::serialize::front_time;

pub(crate) type GetHistoryQuery =
    ListQueryParamsRest<HistoryFilterQueryParamsRest, SortableHistoryColumnRestDTO>;

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[into(CreateHistoryRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateHistoryRequestRestDTO {
    pub action: HistoryAction,
    pub name: String,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    pub source: ExternalHistorySource,
    pub target: Option<String>,
    pub metadata: Option<Value>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(HistoryResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryResponseRestDTO {
    pub id: HistoryId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub entity_id: Option<Uuid>,
    pub entity_type: HistoryEntityType,
    pub organisation_id: Option<OrganisationId>,
    pub source: HistorySource,
    pub target: Option<String>,
    pub user: Option<String>,
}

#[options_not_nullable]
#[derive(Serialize, ToSchema, TryFrom)]
#[try_from(T = HistoryResponseDTO, Error = MapperError)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryResponseDetailRestDTO {
    #[try_from(infallible)]
    pub id: HistoryId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[try_from(infallible)]
    pub created_date: OffsetDateTime,
    #[try_from(infallible)]
    pub action: HistoryAction,
    #[try_from(infallible)]
    pub name: String,
    #[try_from(with_fn = convert_inner, infallible)]
    pub entity_id: Option<Uuid>,
    #[try_from(infallible)]
    pub entity_type: HistoryEntityType,
    #[try_from(infallible)]
    pub organisation_id: Option<OrganisationId>,
    #[try_from(with_fn = try_convert_inner)]
    pub metadata: Option<HistoryMetadataRestEnum>,
    #[try_from(infallible)]
    pub source: HistorySource,
    #[try_from(infallible)]
    pub target: Option<String>,
    #[try_from(with_fn = convert_inner, infallible)]
    pub user: Option<String>,
}

#[derive(Serialize, ToSchema, TryFrom)]
#[try_from(T = one_core::service::history::dto::HistoryMetadataResponse, Error = MapperError)]
pub(crate) enum HistoryMetadataRestEnum {
    UnexportableEntities(UnexportableEntitiesResponseRestDTO),
    ErrorMetadata(#[try_from(infallible)] HistoryErrorMetadataRestDTO),
    WalletUnitJWT(#[try_from(infallible)] String),
    External(#[try_from(infallible)] serde_json::Value),
}

#[derive(Debug, Serialize, ToSchema, TryFrom)]
#[try_from(T = one_core::service::backup::dto::UnexportableEntitiesResponseDTO, Error = MapperError)]
pub(crate) struct UnexportableEntitiesResponseRestDTO {
    #[try_from(with_fn = try_convert_inner)]
    pub credentials: Vec<GetCredentialResponseRestDTO<CredentialDetailClaimResponseRestDTO>>,
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

#[derive(Serialize, ToSchema)]
pub(crate) struct HistoryErrorMetadataRestDTO {
    pub error_code: &'static str,
    pub message: String,
}

impl From<HistoryErrorMetadataDTO> for HistoryErrorMetadataRestDTO {
    fn from(value: HistoryErrorMetadataDTO) -> Self {
        Self {
            error_code: value.error_code.into(),
            message: value.message,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::history::HistoryAction")]
#[into("one_core::model::history::HistoryAction")]
pub enum HistoryAction {
    Accepted,
    Created,
    CsrGenerated,
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
    Reactivated,
    Expired,
    InteractionCreated,
    InteractionErrored,
    InteractionExpired,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::history::HistoryEntityType")]
#[into("one_core::model::history::HistoryEntityType")]
pub enum HistoryEntityType {
    Key,
    Did,
    Certificate,
    Identifier,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
    Backup,
    TrustAnchor,
    TrustEntity,
    WalletUnit,
    User,
    Provider,
    WalletRelyingParty,
    StsRole,
    StsOrganisation,
    StsIamRole,
    StsToken,
    Signature,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from("one_core::model::history::HistorySource")]
#[into("one_core::model::history::HistorySource")]
pub enum HistorySource {
    Core,
    Bridge,
    Sts,
    Wrpr,
    Bff,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into("one_core::model::history::HistorySource")]
pub(crate) enum ExternalHistorySource {
    Bridge,
    Sts,
    Wrpr,
    Bff,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::history::SortableHistoryColumn")]
pub(crate) enum SortableHistoryColumnRestDTO {
    CreatedDate,
    Action,
    EntityType,
    Source,
    User,
    OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HistoryFilterQueryParamsRest {
    /// Return only events associated with the specified entity type(s).
    #[param(rename = "entityTypes[]", inline, nullable = false)]
    pub entity_types: Option<Vec<HistoryEntityType>>,
    /// Return only events associated with the provided entity UUID(s).
    #[param(rename = "entityIds[]", inline, nullable = false)]
    pub entity_ids: Option<Vec<EntityId>>,
    /// Return only events of the specified action(s).
    #[param(rename = "actions[]", inline, nullable = false)]
    pub actions: Option<Vec<HistoryAction>>,
    /// Return only events which occurred after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only events which occurred before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only events associated with the provided Identifier UUID.
    #[param(nullable = false)]
    pub identifier_id: Option<IdentifierId>,
    /// Return only events associated with the provided credential UUID.
    #[param(nullable = false)]
    pub credential_id: Option<CredentialId>,
    /// Return only events associated with the provided credential schema UUID.
    #[param(nullable = false)]
    pub credential_schema_id: Option<CredentialSchemaId>,
    /// Return only events associated with the provided proof schema UUID.
    #[param(nullable = false)]
    pub proof_schema_id: Option<ProofSchemaId>,
    /// Return only events associated with the provided users. Only applicable
    /// in STS authentication mode.
    #[param(rename = "users[]", nullable = false)]
    pub users: Option<Vec<String>>,
    /// Return only events associated with the provided sources.
    #[param(rename = "sources[]", inline, nullable = false)]
    pub sources: Option<Vec<HistorySource>>,
    /// Specify the organizaton(s) from which to return history events.
    #[param(rename = "organisationIds[]", inline, nullable = false)]
    pub organisation_ids: Option<Vec<OrganisationId>>,
    /// Controls cross-organization access. When `false` (default), returns
    /// events from the organization in your STS token, or requires at least
    /// one value in `organisationIds[]` if not using STS authentication.
    /// When `true`, returns events from all organizations; requires
    /// `SYSTEM_HISTORY_LIST` permission in STS authentication mode.
    #[param(inline, nullable = false)]
    pub show_system_history: Option<Boolean>,
}
