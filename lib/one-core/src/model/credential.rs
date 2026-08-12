use proc_macros::Model;
use shared_types::{
    BlobId, CertificateId, CredentialId, CredentialSchemaId, EcosystemId, IdentifierId,
    InteractionId, KeyId, OrganisationId,
};
use strum::{Display, EnumString};
use time::OffsetDateTime;

use super::claim::Claim;
use super::common::GetListResponse;
use super::credential_schema::CredentialSchema;
use super::identifier::Identifier;
use super::interaction::Interaction;
use super::key::Key;
use super::list_query::ListQuery;
use crate::model::certificate::Certificate;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::relation::{Related, RelatedVec};

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct Credential {
    #[model(id)]
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
    pub state: CredentialStateEnum,
    pub suspend_end_date: Option<OffsetDateTime>,
    pub profile: Option<String>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
    pub webhook_url: Option<String>,
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,

    // Relations:
    pub claims: RelatedVec<Claim>,
    pub issuer_identifier: Option<Related<Identifier>>,
    pub issuer_certificate: Option<Related<Certificate>>,
    pub holder_identifier: Option<Related<Identifier>>,
    pub schema: Related<CredentialSchema>,
    pub interaction: Option<Related<Interaction>>,
    pub key: Option<Related<Key>>,
    pub parent: Option<Related<Credential>>,
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
    InteractionExpired,
    Expired,
}

impl CredentialStateEnum {
    pub fn is_terminal(&self) -> bool {
        !Self::non_terminal_states().contains(self)
    }

    pub fn non_terminal_states() -> &'static [Self] {
        &[
            CredentialStateEnum::Created,
            CredentialStateEnum::Pending,
            CredentialStateEnum::Offered,
            CredentialStateEnum::Accepted,
            CredentialStateEnum::Suspended,
        ]
    }
}

#[derive(Clone, Debug)]
pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    Issuer,
    State,
    ExpiresAt,
}

pub type GetCredentialList = GetListResponse<Credential>;
pub type CredentialListQuery =
    ListQuery<SortableCredentialColumn, CredentialFilterValue, CredentialListIncludeEntityTypeEnum>;

#[derive(Clone, Debug, Default)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct UpdateCredentialRequest {
    pub issuer_identifier_id: Option<IdentifierId>,
    pub issuer_certificate_id: Option<CertificateId>,
    pub issuance_date: Option<OffsetDateTime>,
    pub holder_identifier_id: Option<IdentifierId>,
    pub interaction: Option<InteractionId>,
    pub key: Option<KeyId>,
    pub redirect_uri: Option<Option<String>>,
    pub state: Option<CredentialStateEnum>,
    pub expires_at: Option<OffsetDateTime>,
    pub suspend_end_date: Clearable<Option<OffsetDateTime>>,
    pub consumed_at: Clearable<Option<OffsetDateTime>>,
    pub wallet_unit_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,

    pub claims: Option<Vec<Claim>>,
    pub credential_blob_id: Option<BlobId>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Display)]
pub enum CredentialRole {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Display)]
pub enum CredentialType {
    Single,
    BatchParent,
    BatchItem,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub enum Clearable<T> {
    ForceSet(T),
    #[default]
    DontTouch,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CredentialFilterValue {
    ClaimName(StringMatch),
    ClaimValue(StringMatch),
    CredentialSchemaName(StringMatch),
    OrganisationId(OrganisationId),
    Roles(Vec<CredentialRole>),
    CredentialIds(Vec<CredentialId>),
    ParentCredential(CredentialId),
    Consumed(bool),
    CredentialSchemaIds(Vec<CredentialSchemaId>),
    SchemaId(String),
    IssuerIds(Vec<IdentifierId>),
    States(Vec<CredentialStateEnum>),
    Types(Vec<CredentialType>),
    SuspendEndDate(ValueComparison<OffsetDateTime>),
    Profiles(Vec<String>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
    IssuanceDate(ValueComparison<OffsetDateTime>),
    RevocationDate(ValueComparison<OffsetDateTime>),
    ExpiresAt(ValueComparison<OffsetDateTime>),
    HasUnconsumedBatchItems(bool),
    Deleted(bool),
}

impl ListFilterValue for CredentialFilterValue {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExactCredentialFilterColumn {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, EnumString, Display)]
#[strum(serialize_all = "camelCase")]
pub enum CredentialListIncludeEntityTypeEnum {
    LayoutProperties,
    Translations,
}
