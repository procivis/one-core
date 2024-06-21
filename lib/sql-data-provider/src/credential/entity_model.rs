use sea_orm::FromQueryResult;
use shared_types::{CredentialId, DidId, DidValue};
use time::OffsetDateTime;

use crate::entity::credential_schema::{CredentialSchemaType, LayoutProperties, WalletStorageType};
use crate::entity::did::DidType;
use crate::entity::{credential, credential_state};

#[derive(FromQueryResult)]
pub(super) struct CredentialListEntityModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub exchange: String,
    pub credential: Vec<u8>,
    pub redirect_uri: Option<String>,
    pub role: credential::CredentialRole,
    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_format: String,
    pub credential_schema_id: String,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: String,
    pub credential_schema_revocation_method: String,
    pub credential_schema_wallet_storage_type: Option<WalletStorageType>,
    pub credential_schema_schema_id: String,
    pub credential_schema_schema_layout_properties: Option<LayoutProperties>,
    pub credential_schema_schema_type: CredentialSchemaType,
    pub credential_state_created_date: OffsetDateTime,
    pub credential_state_state: credential_state::CredentialState,
    pub credential_state_suspend_end_date: Option<OffsetDateTime>,
    pub issuer_did_created_date: Option<OffsetDateTime>,
    pub issuer_did_deactivated: Option<bool>,
    pub issuer_did_did: Option<DidValue>,
    pub issuer_did_id: Option<DidId>,
    pub issuer_did_last_modified: Option<OffsetDateTime>,
    pub issuer_did_method: Option<String>,
    pub issuer_did_name: Option<String>,
    pub issuer_did_type_field: Option<DidType>,
}

#[derive(FromQueryResult)]
pub(super) struct CredentialCountEntityModel {
    pub count: i64,
}
