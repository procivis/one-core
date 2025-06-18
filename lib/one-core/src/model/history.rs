use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, CredentialSchemaId, EntityId, HistoryId, IdentifierId, OrganisationId,
    ProofSchemaId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;
use crate::service::error::ErrorCode;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HistoryMetadata {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
    ErrorMetadata(HistoryErrorMetadata),
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
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub metadata: Option<HistoryMetadata>,
    pub organisation_id: Option<OrganisationId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableHistoryColumn {
    CreatedDate,
    Action,
    EntityType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryFilterValue {
    EntityTypes(Vec<HistoryEntityType>),
    EntityId(EntityId),
    EntityIds(Vec<EntityId>),
    Actions(Vec<HistoryAction>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    IdentifierId(IdentifierId),
    CredentialId(CredentialId),
    CredentialSchemaId(CredentialSchemaId),
    SearchQuery(String, HistorySearchEnum),
    OrganisationId(OrganisationId),
    ProofSchemaId(ProofSchemaId),
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
