use one_core::model::credential_schema::CredentialSchemaName;
use sea_orm::FromQueryResult;
use serde::Deserialize;
use shared_types::{
    BlobId, CredentialFormat, CredentialId, CredentialSchemaId, IdentifierId, OrganisationId,
    RevocationMethodId,
};
use time::OffsetDateTime;

use crate::entity::credential::{CredentialRole, CredentialState};
use crate::entity::credential_schema::KeyStorageSecurity;
use crate::entity::{claim, claim_schema};

#[derive(Debug, FromQueryResult)]
pub struct UnexportableCredentialModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub state: CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,

    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: CredentialSchemaName,
    pub credential_schema_format: CredentialFormat,
    pub credential_schema_revocation_method: Option<RevocationMethodId>,
    pub credential_schema_key_storage_security: Option<KeyStorageSecurity>,
    pub credential_schema_imported_source_url: String,
    pub credential_schema_allow_suspension: bool,
    pub credential_schema_requires_app_attestation: bool,

    pub organisation_id: OrganisationId,
    pub organisation_name: String,
    pub organisation_created_date: OffsetDateTime,
    pub organisation_last_modified: OffsetDateTime,
    pub organisation_deactivated_at: Option<OffsetDateTime>,
    pub organisation_wallet_provider: Option<String>,
    pub organisation_wallet_provider_issuer: Option<IdentifierId>,

    pub credential_blob_id: Option<BlobId>,

    pub claims: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimWithSchema {
    pub claim: claim::Model,
    pub claim_schema: claim_schema::Model,
}
