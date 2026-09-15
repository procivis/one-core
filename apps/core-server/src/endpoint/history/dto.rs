use one_core::model::history::HistorySearchEnum;
use one_core::service::error::ServiceError;
use one_core::service::history::dto::{
    HistoryErrorMetadataDTO, HistoryFilterParamsDTO, HistoryResponseDTO,
};
use one_dto_mapper::{
    From, Into, TryFrom, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId, ProofId,
    ProofSchemaId, TrustCollectionId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ecosystem::EcosystemOutcomesRestDTO;
use crate::dto::common::trust_detail::TrustResolutionResultRestEnum;
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
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateHistoryRequestRestDTO {
    /// The action that occurred on the entity.
    pub action: HistoryAction,
    /// Display name of the entity at the time the event was recorded. For
    /// credential events, this is the credential schema name; for proof
    /// events, this is the proof schema name.
    pub name: String,
    /// UUID of the entity the event relates to.
    pub entity_id: Option<EntityId>,
    /// Type of entity the event relates to.
    pub entity_type: HistoryEntityType,
    /// Organization the event belongs to.
    pub organisation_id: Option<OrganisationId>,
    /// The external service submitting this event. Must not be `CORE`.
    pub source: ExternalHistorySource,
    /// External participant in the interaction, if applicable.
    pub target: Option<String>,
    /// Optional structured metadata attached to the event.
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
    /// Service that recorded the event.
    pub source: HistorySource,
    /// Identifier UUID of the external participant in the interaction, if
    /// applicable. For credential events, this is the counterpart's identifier
    /// (holder when the system is issuer, issuer when the system is holder).
    /// For presentation events, this is the holder's identifier when the system
    /// is verifier, or the verifier's identifier when the system is holder.
    pub target: Option<String>,
    /// Identifier of the user who triggered the event. Present only when
    /// STS authentication is in use.
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
    /// Structured metadata attached to the event. The variant present
    /// depends on the event type.
    #[try_from(with_fn = try_convert_inner)]
    pub metadata: Option<HistoryMetadataRestEnum>,
    /// Service that recorded the event.
    #[try_from(infallible)]
    pub source: HistorySource,
    /// Secondary entity involved in the event, if any.
    #[try_from(infallible)]
    pub target: Option<String>,
    #[try_from(with_fn = convert_inner, infallible)]
    /// Identifier of the user who triggered the event. Present only when
    /// STS authentication is in use.
    pub user: Option<String>,
}

#[derive(Serialize, ToSchema, TryFrom)]
#[try_from(T = one_core::service::history::dto::HistoryMetadataResponse, Error = MapperError)]
pub(crate) enum HistoryMetadataRestEnum {
    /// Items lost during finalization of a backup.
    UnexportableEntities(UnexportableEntitiesResponseRestDTO),
    /// Metadata for error events.
    ErrorMetadata(#[try_from(infallible)] HistoryErrorMetadataRestDTO),
    /// The hash of a wallet unit's JWT.
    WalletUnitJWT(#[try_from(infallible)] String),
    /// Additional information from non-Core services recording history
    /// events.
    External(#[try_from(infallible)] serde_json::Value),
    /// The name of the WRP the event relates to.
    WalletRelyingParty(#[try_from(infallible)] WalletRelyingPartyMetadataRestDTO),
    /// The trust resolution verdict.
    TrustResolution(#[try_from(infallible)] TrustResolutionMetadataRestDTO),
    /// One entry per ecosystem provider consulted, keyed by provider id.
    EcosystemsResolved(#[try_from(infallible)] EcosystemOutcomesRestDTO),
}

#[derive(Debug, Clone, Serialize, From, ToSchema)]
#[from(one_core::service::history::dto::TrustResolutionMetadataDTO)]
pub struct TrustResolutionMetadataRestDTO {
    pub result: TrustResolutionResultRestEnum,
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

#[derive(Debug, Clone, Serialize, ToSchema, From)]
#[from(one_core::service::history::dto::WalletRelyingPartyMetadataDTO)]
pub(crate) struct WalletRelyingPartyMetadataRestDTO {
    pub name: Option<String>,
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
    Expiring,
    InteractionCreated,
    InteractionErrored,
    InteractionExpired,
    Delivered,
    WrpAcReceived,
    WrpRcReceived,
    WrpNrReceived,
    TrustResolved,
    EcosystemsResolved,
    Refreshed,
    Signed,
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
    Instance,
    ManagedInstance,
    User,
    Provider,
    WalletRelyingParty,
    StsRole,
    StsOrganisation,
    StsIamRole,
    StsSession,
    StsToken,
    Signature,
    Notification,
    SupervisoryAuthority,
    TrustListPublication,
    TrustCollection,
    TrustListSubscription,
    QesDocument,
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
    Qtsp,
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

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(HistorySearchEnum)]
pub(crate) enum HistorySearchTypeRestEnum {
    All,
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
    IssuerDid,
    IssuerName,
    VerifierDid,
    VerifierName,
    ProofSchemaName,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = HistoryFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetHistoryQuery
pub(crate) struct HistoryFilterQueryParamsRest {
    /// Return only events associated with the specified entity type(s).
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "entityTypes[]", inline, nullable = false)]
    pub entity_types: Option<Vec<HistoryEntityType>>,
    /// Return only events associated with the provided entity UUID(s).
    #[param(rename = "entityIds[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub entity_ids: Option<Vec<EntityId>>,
    /// Return only events of the specified action(s).
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "actions[]", inline, nullable = false)]
    pub actions: Option<Vec<HistoryAction>>,
    /// Return only events which occurred after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only events which occurred before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only events associated with the provided identifier UUID.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub identifier_id: Option<IdentifierId>,
    /// Return only events associated with the provided credential UUID.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub credential_id: Option<CredentialId>,
    /// Return only events associated with the provided proof UUID.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub proof_id: Option<ProofId>,
    /// Return only events associated with the provided credential schema UUID.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub credential_schema_id: Option<CredentialSchemaId>,
    /// Return only events associated with the provided proof schema UUID.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub proof_schema_id: Option<ProofSchemaId>,
    /// Return only events associated with the provided trust collection UUID.
    /// Includes the collection's own events and the events of all trust list
    /// subscriptions it contains.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub trust_collection_id: Option<TrustCollectionId>,
    /// Return only events associated with the provided users. Only applicable
    /// in STS authentication mode.
    #[param(rename = "users[]", nullable = false)]
    #[try_into(infallible)]
    pub users: Option<Vec<String>>,
    /// Return only events associated with the provided sources.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "sources[]", inline, nullable = false)]
    pub sources: Option<Vec<HistorySource>>,
    /// Specify the organizaton(s) from which to return history events.
    #[param(rename = "organisationIds[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub organisation_ids: Option<Vec<OrganisationId>>,
    /// Search for a string. Pass a `searchType` to control which field
    /// is searched. When omitted, defaults to searching all fields.
    #[param(nullable = false)]
    #[try_into(infallible, rename = "search_query")]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. If no value is provided, events
    /// that have any field matching `searchText` will be returned.
    #[try_into(infallible, with_fn = convert_inner, rename = "search_type")]
    #[param(inline, nullable = false)]
    pub search_type: Option<HistorySearchTypeRestEnum>,
    /// Controls cross-organization access. When `false` (default), returns
    /// events from the organization in your STS token, or requires at least
    /// one value in `organisationIds[]` if not using STS authentication.
    /// When `true`, returns events from all organizations; requires
    /// `SYSTEM_HISTORY_LIST` permission in STS authentication mode.
    #[param(inline, nullable = false)]
    #[try_into(skip)]
    pub show_system_history: Option<Boolean>,
}
