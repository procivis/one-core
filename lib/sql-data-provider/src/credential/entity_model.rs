use sea_orm::FromQueryResult;
use shared_types::{
    BlobId, CertificateId, CredentialId, CredentialSchemaFormatId, CredentialSchemaId, DidId,
    EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId,
};
use time::OffsetDateTime;

use crate::entity::credential;
use crate::entity::credential_schema::{KeyStorageSecurity, LayoutProperties, TransactionCodeType};
use crate::entity::identifier::{IdentifierState, IdentifierType};

#[derive(FromQueryResult)]
pub(super) struct CredentialListEntityModel {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub deleted_at: Option<OffsetDateTime>,
    pub consumed_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: credential::CredentialRole,
    pub r#type: credential::CredentialType,
    pub state: credential::CredentialState,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub parent_id: Option<CredentialId>,
    pub key_id: Option<KeyId>,
    pub interaction_id: Option<InteractionId>,
    pub holder_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_key_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
    pub webhook_url: Option<String>,
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,
    pub format: Option<CredentialSchemaFormatId>,

    pub credential_schema_deleted_at: Option<OffsetDateTime>,
    pub credential_schema_created_date: OffsetDateTime,
    pub credential_schema_id: CredentialSchemaId,
    pub credential_schema_last_modified: OffsetDateTime,
    pub credential_schema_name: String,
    pub credential_schema_key_storage_security: Option<KeyStorageSecurity>,
    pub credential_schema_organisation_id: OrganisationId,
    pub credential_schema_imported_source_url: String,
    pub credential_schema_allow_suspension: bool,
    pub credential_schema_requires_wallet_instance_attestation: bool,
    pub credential_schema_schema_layout_properties: Option<LayoutProperties>,
    pub credential_schema_transaction_code_type: Option<TransactionCodeType>,
    pub credential_schema_transaction_code_length: Option<i32>,
    pub credential_schema_transaction_code_description: Option<String>,
    pub credential_schema_batch_size: Option<i32>,
    pub credential_schema_allow_revocation: bool,
    pub credential_schema_embedded_disclosure_policy: Option<String>,
    pub credential_schema_expiration: Option<i32>,
    pub credential_schema_ecosystem: Option<EcosystemId>,
    pub credential_schema_preferred_key_storage_attestation_lifetime: Option<i32>,
    pub credential_schema_preferred_instance_attestation_lifetime: Option<i32>,

    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_identifier_created_date: Option<OffsetDateTime>,
    pub issuer_identifier_last_modified: Option<OffsetDateTime>,
    pub issuer_identifier_name: Option<String>,
    pub issuer_identifier_type: Option<IdentifierType>,
    pub issuer_identifier_is_remote: Option<bool>,
    pub issuer_identifier_state: Option<IdentifierState>,
    pub issuer_identifier_organisation_id: Option<OrganisationId>,
    pub issuer_identifier_did_id: Option<DidId>,
    pub issuer_identifier_key_id: Option<KeyId>,
}
