use proc_macros::Model;
use shared_types::{CredentialFormat, CredentialSchemaFormatId, CredentialSchemaId};
use time::OffsetDateTime;

use super::credential_schema_format_claim_schema::CredentialSchemaFormatClaimSchema;
use super::relation::RelatedVec;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct CredentialSchemaFormat {
    #[model(id)]
    pub id: CredentialSchemaFormatId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema_id: CredentialSchemaId,
    pub format: CredentialFormat,
    pub ecosystem_schema_id: String,
    pub claim_mappings: RelatedVec<CredentialSchemaFormatClaimSchema>,
}
