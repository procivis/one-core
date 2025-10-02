use sea_orm::FromQueryResult;
use shared_types::{BlobId, CredentialId, CredentialSchemaId, IdentifierId};
use time::OffsetDateTime;

use crate::entity::credential;
use crate::entity::credential_schema::{CredentialSchemaType, LayoutProperties, WalletStorageType};
use crate::entity::identifier::{IdentifierState, IdentifierType};

#[derive(FromQueryResult)]
pub(super) struct CredentialListEntityModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: credential::CredentialRole,
    pub state: credential::CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,

    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_format: String,
    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: String,
    pub credential_schema_revocation_method: String,
    pub credential_schema_wallet_storage_type: Option<WalletStorageType>,
    pub credential_schema_schema_id: String,
    pub credential_schema_imported_source_url: String,
    pub credential_schema_schema_type: CredentialSchemaType,
    pub credential_schema_allow_suspension: bool,
    pub credential_schema_external_schema: bool,
    pub credential_schema_schema_layout_properties: Option<LayoutProperties>,

    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_identifier_created_date: Option<OffsetDateTime>,
    pub issuer_identifier_last_modified: Option<OffsetDateTime>,
    pub issuer_identifier_name: Option<String>,
    pub issuer_identifier_type: Option<IdentifierType>,
    pub issuer_identifier_is_remote: Option<bool>,
    pub issuer_identifier_state: Option<IdentifierState>,
}
