use one_core::model::credential_schema::CredentialSchemaName;
use sea_orm::FromQueryResult;
use serde::Deserialize;
use shared_types::{BlobId, CredentialId, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;

use crate::entity::credential::{CredentialRole, CredentialState, CredentialType};
use crate::entity::credential_schema::{KeyStorageSecurity, TransactionCodeType};
use crate::entity::{claim, claim_schema};

#[derive(Debug, FromQueryResult)]
pub struct UnexportableCredentialModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub r#type: CredentialType,
    pub state: CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub webhook_url: Option<String>,
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,

    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: CredentialSchemaName,
    pub credential_schema_key_storage_security: Option<KeyStorageSecurity>,
    pub credential_schema_imported_source_url: String,
    pub credential_schema_allow_suspension: bool,
    pub credential_schema_requires_wallet_instance_attestation: bool,
    pub credential_schema_transaction_code_type: Option<TransactionCodeType>,
    pub credential_schema_transaction_code_length: Option<i32>,
    pub credential_schema_transaction_code_description: Option<String>,
    pub credential_schema_batch_size: Option<i32>,
    pub credential_schema_allow_revocation: bool,
    pub credential_schema_embedded_disclosure_policy: Option<String>,
    pub credential_schema_expiration: Option<i32>,

    pub organisation_id: OrganisationId,

    pub parent_id: Option<CredentialId>,
    pub credential_blob_id: Option<BlobId>,

    pub claims: String,
}

#[derive(Debug, Deserialize)]
pub struct ClaimWithSchema {
    pub claim: claim::Model,
    pub claim_schema: claim_schema::Model,
}
