use serde::{Deserialize, Serialize};
use shared_types::{
    CredentialId, CredentialSchemaId, DidId, EntityId, HistoryId, OrganisationId, ProofSchemaId,
};
use time::OffsetDateTime;

use super::organisation::Organisation;
use crate::model::common::GetListResponse;
use crate::model::list_filter::{ListFilterValue, ValueComparison};
use crate::model::list_query::ListQuery;
use crate::service::backup::dto::UnexportableEntitiesResponseDTO;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HistoryMetadata {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
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
    pub entity_id: Option<EntityId>,
    pub entity_type: HistoryEntityType,
    pub metadata: Option<HistoryMetadata>,

    // Relations
    pub organisation: Option<Organisation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    Action(HistoryAction),
    CreatedDate(ValueComparison<OffsetDateTime>),
    DidId(DidId),
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
