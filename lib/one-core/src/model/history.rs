use serde::{Deserialize, Serialize};
use shared_types::{CredentialId, DidId, EntityId, HistoryId, OrganisationId};
use time::OffsetDateTime;

use crate::{
    model::{
        common::GetListResponse,
        credential_schema::CredentialSchemaId,
        list_filter::{ListFilterValue, ValueComparison},
        list_query::ListQuery,
    },
    service::backup::dto::UnexportableEntitiesResponseDTO,
};

use super::organisation::Organisation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HistoryMetadata {
    UnexportableEntities(UnexportableEntitiesResponseDTO),
}

impl From<UnexportableEntitiesResponseDTO> for HistoryMetadata {
    fn from(value: UnexportableEntitiesResponseDTO) -> Self {
        Self::UnexportableEntities(value)
    }
}

#[derive(Clone)]
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
    Issued,
    Offered,
    Reactivated,
    Rejected,
    Requested,
    Revoked,
    Pending,
    Suspended,
    Restored,
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
}

impl ListFilterValue for HistoryFilterValue {}

pub type GetHistoryList = GetListResponse<History>;
pub type HistoryListQuery = ListQuery<SortableHistoryColumn, HistoryFilterValue>;
