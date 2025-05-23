use one_core::model::credential_schema::{
    CredentialFormat, CredentialSchemaName, RevocationMethod,
};
use sea_orm::FromQueryResult;
use serde::Deserialize;
use shared_types::{CredentialId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;

use crate::entity::credential::{CredentialRole, CredentialState};
use crate::entity::credential_schema::WalletStorageType;
use crate::entity::{claim, claim_schema, credential_schema_claim_schema};

#[derive(Debug, FromQueryResult)]
pub struct UnexportableCredentialModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub credential: Vec<u8>,
    pub exchange: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub state: CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,

    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: CredentialSchemaName,
    pub credential_schema_format: CredentialFormat,
    pub credential_schema_revocation_method: RevocationMethod,
    pub credential_schema_wallet_storage_type: Option<WalletStorageType>,
    pub credential_schema_external_schema: bool,
    pub credential_schema_imported_source_url: String,
    pub credential_schema_allow_suspension: bool,

    pub organisation_id: OrganisationId,
    pub organisation_name: String,
    pub organisation_created_date: OffsetDateTime,
    pub organisation_last_modified: OffsetDateTime,

    pub claims: String,
    pub credential_schema_claim_schemas: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimWithSchema {
    pub claim: claim::Model,
    pub claim_schema: claim_schema::Model,
}

#[derive(Debug, Deserialize)]
pub struct SchemaWithClaimSchema {
    pub credential_schema_claim_schema: credential_schema_claim_schema::Model,
    pub claim_schema: claim_schema::Model,
}
