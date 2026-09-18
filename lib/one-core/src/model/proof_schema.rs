use proc_macros::Model;
use shared_types::{EcosystemId, ProofSchemaId};
use time::OffsetDateTime;

use super::claim_schema::ClaimSchema;
use super::common::GetListResponse;
use super::credential_schema::CredentialSchema;
use super::list_query::ListQuery;
use super::organisation::Organisation;
use crate::model::relation::{Related, RelatedVec};
use crate::service::proof_schema::dto::ProofSchemaFilterValue;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ProofSchema {
    #[model(id)]
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,
    pub imported_source_url: Option<String>,
    pub ecosystem: Option<EcosystemId>,

    // Relations
    pub organisation: Related<Organisation>,
    pub input_schemas: RelatedVec<ProofInputSchema>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ProofInputSchema {
    // Relations
    pub claim_schemas: RelatedVec<ProofInputClaimSchema>,
    pub credential_schema: Related<CredentialSchema>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct ProofInputClaimSchema {
    pub schema: ClaimSchema,
    pub required: bool,
    pub order: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactProofSchemaFilterColumn {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofSchemaColumn {
    Name,
    CreatedDate,
}

pub type GetProofSchemaList<Count = Option<u64>> = GetListResponse<ProofSchema, Count>;
pub type ProofSchemaListQuery = ListQuery<SortableProofSchemaColumn, ProofSchemaFilterValue>;
