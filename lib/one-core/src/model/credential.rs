use shared_types::{BlobId, CertificateId, CredentialId, IdentifierId, KeyId};
use strum::Display;
use time::OffsetDateTime;

use super::claim::{Claim, ClaimRelations};
use super::common::GetListResponse;
use super::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use super::identifier::{Identifier, IdentifierRelations};
use super::interaction::{Interaction, InteractionId, InteractionRelations};
use super::key::Key;
use super::list_query::ListQuery;
use super::revocation_list::{RevocationList, RevocationListRelations};
use crate::model::certificate::{Certificate, CertificateRelations};
use crate::model::key::KeyRelations;
use crate::service::credential::dto::{CredentialFilterValue, CredentialListIncludeEntityTypeEnum};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub issuance_date: Option<OffsetDateTime>,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub redirect_uri: Option<String>,
    pub role: CredentialRole,
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub credential_blob_id: Option<BlobId>,

    // Relations:
    pub claims: Option<Vec<Claim>>,
    pub issuer_identifier: Option<Identifier>,
    pub issuer_certificate: Option<Certificate>,
    pub holder_identifier: Option<Identifier>,
    pub schema: Option<CredentialSchema>,
    pub interaction: Option<Interaction>,
    pub revocation_list: Option<RevocationList>,
    pub key: Option<Key>,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CredentialRelations {
    pub claims: Option<ClaimRelations>,
    pub issuer_identifier: Option<IdentifierRelations>,
    pub issuer_certificate: Option<CertificateRelations>,
    pub holder_identifier: Option<IdentifierRelations>,
    pub schema: Option<CredentialSchemaRelations>,
    pub interaction: Option<InteractionRelations>,
    pub revocation_list: Option<RevocationListRelations>,
    pub key: Option<KeyRelations>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Display)]
pub enum CredentialStateEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Suspended,
    Error,
}

pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    Issuer,
    State,
}

pub type GetCredentialList = GetListResponse<Credential>;
pub type GetCredentialQuery =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UpdateCredentialRequest {
    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub issuance_date: Option<OffsetDateTime>,
    pub holder_identifier_id: Option<IdentifierId>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
    pub state: Option<CredentialStateEnum>,
    pub suspend_end_date: Clearable<Option<OffsetDateTime>>,

    pub claims: Option<Vec<Claim>>,
    pub credential_blob_id: Option<BlobId>,
}

#[derive(Clone, Debug, PartialEq, Eq, Display)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum Clearable<T> {
    ForceSet(T),
    #[default]
    DontTouch,
}
