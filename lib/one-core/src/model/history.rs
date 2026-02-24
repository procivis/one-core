use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId, ProofId,
    ProofSchemaId,
};
use time::OffsetDateTime;

use crate::error::ErrorCode;
use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HistoryMetadata {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
    ErrorMetadata(HistoryErrorMetadata),
    WalletUnitJWT(String),
    External(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryErrorMetadata {
    pub error_code: ErrorCode,
    pub message: String,
}

impl From<UnexportableEntitiesResponseDTO> for HistoryMetadata {
    fn from(value: UnexportableEntitiesResponseDTO) -> Self {
        Self::UnexportableEntities(value)
    }
}

#[derive(Clone, Debug)]
pub struct History {
    pub id: HistoryId,
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub name: String,
    pub target: Option<String>,
    pub source: HistorySource,
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub metadata: Option<HistoryMetadata>,
    pub organisation_id: Option<OrganisationId>,
    pub user: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
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
    Delivered,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HistoryEntityType {
    Key,
    Did,
    Identifier,
    Certificate,
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
    StsSession,
    StsToken,
    Signature,
    Notification,
    SupervisoryAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HistorySource {
    Core,
    Bridge,
    Sts,
    Wrpr,
    Bff,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableHistoryColumn {
    CreatedDate,
    Action,
    EntityType,
    Source,
    User,
    OrganisationId,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryFilterValue {
    EntityTypes(Vec<HistoryEntityType>),
    EntityIds(Vec<EntityId>),
    Actions(Vec<HistoryAction>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    IdentifierId(IdentifierId),
    CredentialId(CredentialId),
    CredentialSchemaId(CredentialSchemaId),
    SearchQuery(String, HistorySearchEnum),
    OrganisationIds(Vec<OrganisationId>),
    ProofId(ProofId),
    ProofSchemaId(ProofSchemaId),
    Users(Vec<String>),
    Sources(Vec<HistorySource>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistorySearchEnum {
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

impl ListFilterValue for HistoryFilterValue {}

pub type GetHistoryList = GetListResponse<History>;
pub type HistoryListQuery = ListQuery<SortableHistoryColumn, HistoryFilterValue>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganisationStats {
    pub previous: Option<OrganisationSummaryStats>,
    pub current: OrganisationSummaryStats,
    pub timelines: OrganisationTimelines,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganisationSummaryStats {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganisationTimelines {
    pub issuer: IssuerTimelines,
    pub verifier: VerifierTimelines,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerTimelines {
    pub offered: Vec<TimeSeriesPoint>,
    pub issued: Vec<TimeSeriesPoint>,
    pub rejected: Vec<TimeSeriesPoint>,
    pub suspended: Vec<TimeSeriesPoint>,
    pub reactivated: Vec<TimeSeriesPoint>,
    pub revoked: Vec<TimeSeriesPoint>,
    pub error: Vec<TimeSeriesPoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifierTimelines {
    pub pending: Vec<TimeSeriesPoint>,
    pub accepted: Vec<TimeSeriesPoint>,
    pub rejected: Vec<TimeSeriesPoint>,
    pub error: Vec<TimeSeriesPoint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSeriesPoint {
    pub timestamp: OffsetDateTime,
    pub count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemStats {
    pub previous: Option<SystemOperationsCount>,
    pub current: SystemOperationsCount,
    pub top_issuers: Vec<OrganisationOperationsCount>,
    pub top_verifiers: Vec<OrganisationOperationsCount>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganisationOperationsCount {
    pub organisation_id: OrganisationId,
    pub current: usize,
    pub previous: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemOperationsCount {
    pub issuance_count: usize,
    pub verification_count: usize,
    pub credential_lifecycle_operation_count: usize,
    pub session_token_count: usize,
    pub active_wallet_unit_count: usize,
}
