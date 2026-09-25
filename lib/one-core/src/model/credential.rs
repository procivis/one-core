use proc_macros::Model;
use shared_types::{
    BlobId, CertificateId, CredentialFormat, CredentialId, CredentialSchemaFormatId,
    CredentialSchemaId, EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId,
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
use crate::error::NestedError;
use crate::model::certificate::Certificate;
use crate::model::credential_schema_format::CredentialSchemaFormat;
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
    pub wallet_key_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
    pub webhook_url: Option<String>,
    /// Holder configuration policy, stored on singles and batch items, not batch parents.
    pub embedded_disclosure_policy: Option<String>,
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,

    // Relations:
    pub claims: RelatedVec<Claim>,
    pub issuer_identifier: Option<Related<Identifier>>,
    pub issuer_certificate: Option<Related<Certificate>>,
    pub holder_identifier: Option<Related<Identifier>>,
    pub schema: Related<CredentialSchema>,
    pub format: Option<Related<CredentialSchemaFormat>>,
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
    Expiring,
    Expired,
}

impl Credential {
    /// The credential that holds the relevant ecosystem history events.
    /// Points to the batch parent for credentials of type [CredentialType::BatchItem]
    pub(crate) fn ecosystem_history_id(&self) -> CredentialId {
        self.parent
            .as_ref()
            .map(|parent| parent.id())
            .unwrap_or(self.id)
    }

    pub(crate) fn is_available_for_presentation(&self, now: OffsetDateTime) -> bool {
        if self.deleted_at.is_some() || self.state != CredentialStateEnum::Accepted {
            return false;
        }
        match self.r#type {
            CredentialType::Single => true,
            CredentialType::BatchParent => false,
            CredentialType::BatchItem => {
                self.consumed_at.is_none() && self.expires_at.is_none_or(|expiry| expiry > now)
            }
        }
    }

    /// Returns the concrete credential's format. Batch parents return `None`, even if
    /// they retain a legacy format in storage; use their items' formats instead.
    pub async fn credential_format(&self) -> Result<Option<CredentialFormat>, NestedError> {
        if self.r#type == CredentialType::BatchParent {
            return Ok(None);
        }
        match &self.format {
            Some(format) => Ok(Some(format.as_ref().await?.format.to_owned())),
            None => Ok(None),
        }
    }
}

impl CredentialStateEnum {
    pub fn is_terminal(&self) -> bool {
        !Self::non_terminal_states().contains(self)
    }

    pub fn non_terminal_states() -> &'static [Self] {
        &[
            CredentialStateEnum::Expiring,
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

pub type GetCredentialList<Count = Option<u64>> = GetListResponse<Credential, Count>;
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
    pub wallet_key_attestation_blob_id: Option<BlobId>,
    pub wallet_instance_attestation_blob_id: Option<BlobId>,

    pub credential_blob_id: Option<BlobId>,
    pub format: Option<CredentialSchemaFormatId>,
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
    ParentCredentials(Vec<CredentialId>),
    Consumed(bool),
    CredentialSchemaIds(Vec<CredentialSchemaId>),
    Ecosystems(Vec<EcosystemId>),
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
    FormatIds(Vec<CredentialSchemaFormatId>),
    Formats(Vec<CredentialFormat>),
    HasUnconsumedBatchItems(bool),
    /// The accepted, non-deleted, unconsumed item with the earliest expiry per parent and format.
    /// Items without an expiry sort last; ties are broken by descending ID.
    EarliestExpiringBatchItemPerFormat,
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
