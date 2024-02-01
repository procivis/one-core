use shared_types::{DidId, EntityId, HistoryId};
use time::OffsetDateTime;

use crate::model::{
    common::GetListResponse, credential::CredentialId, credential_schema::CredentialSchemaId,
    list_filter::ListFilterValue, list_query::ListQuery,
};

use super::organisation::{Organisation, OrganisationId};

#[derive(Clone)]
pub struct History {
    pub id: HistoryId,
    pub created_date: OffsetDateTime,
    pub action: HistoryAction,
    pub entity_id: EntityId,
    pub entity_type: HistoryEntityType,

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
    Rejected,
    Requested,
    Revoked,
    Pending,
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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableHistoryColumn {
    CreatedDate,
    Action,
    EntityType,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HistoryFilterValue {
    EntityType(HistoryEntityType),
    EntityId(EntityId),
    Action(HistoryAction),
    CreatedDateFrom(OffsetDateTime),
    CreatedDateTo(OffsetDateTime),
    DidId(DidId),
    CredentialId(CredentialId),
    CredentialSchemaId(CredentialSchemaId),
    OrganisationId(OrganisationId),
}

impl ListFilterValue for HistoryFilterValue {}

pub type GetHistoryList = GetListResponse<History>;
pub type HistoryListQuery = ListQuery<SortableHistoryColumn, HistoryFilterValue>;
