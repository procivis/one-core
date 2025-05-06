use sea_orm::FromQueryResult;
use shared_types::{CredentialId, CredentialSchemaId, DidId, DidValue, IdentifierId};
use time::OffsetDateTime;

use crate::entity::credential;
use crate::entity::credential_schema::{CredentialSchemaType, LayoutProperties, WalletStorageType};
use crate::entity::did::DidType;
use crate::entity::identifier::{IdentifierStatus, IdentifierType};

#[derive(FromQueryResult)]
pub(super) struct CredentialListEntityModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub exchange: String,
    pub credential: Option<Vec<u8>>,
    pub redirect_uri: Option<String>,
    pub role: credential::CredentialRole,
    pub state: credential::CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,
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
    pub credential_schema_schema_layout_properties: Option<LayoutProperties>,
    pub credential_schema_schema_type: CredentialSchemaType,
    pub credential_schema_allow_suspension: bool,
    pub credential_schema_external_schema: bool,

    pub issuer_did_created_date: Option<OffsetDateTime>,
    pub issuer_did_deactivated: Option<bool>,
    pub issuer_did_did: Option<DidValue>,
    pub issuer_did_id: Option<DidId>,
    pub issuer_did_last_modified: Option<OffsetDateTime>,
    pub issuer_did_method: Option<String>,
    pub issuer_did_name: Option<String>,
    pub issuer_did_type_field: Option<DidType>,

    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_identifier_created_date: Option<OffsetDateTime>,
    pub issuer_identifier_last_modified: Option<OffsetDateTime>,
    pub issuer_identifier_name: Option<String>,
    pub issuer_identifier_type: Option<IdentifierType>,
    pub issuer_identifier_is_remote: Option<bool>,
    pub issuer_identifier_status: Option<IdentifierStatus>,
}
