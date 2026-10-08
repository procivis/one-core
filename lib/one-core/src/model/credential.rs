use proc_macros::Model;
use shared_types::{
    BlobId, CertificateId, CredentialFormat, CredentialId, CredentialSchemaFormatId,
    CredentialSchemaId, EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId,
};
use strum::{Display, EnumString, IntoStaticStr};
use time::OffsetDateTime;

use super::claim::Claim;
use super::common::GetListResponse;
use super::credential_schema::CredentialSchema;
use super::identifier::Identifier;
use super::interaction::Interaction;
use super::key::Key;
use super::list_query::ListQuery;
use crate::error::{ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt, NestedError};
use crate::model::certificate::Certificate;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::HistoryErrorMetadata;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::relation::{Related, RelatedVec};

#[derive(Clone, Debug, Model, IntoStaticStr)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub enum Credential {
    IssuerSingle {
        #[model(nested)]
        common: CredentialCommon,
        issuer: IssuerData,
        webhook_url: Option<String>,
        /// Optional, opaque metadata to allow external clients to store metadata on credentials.
        /// Shared by an entire issuance: batch items read it through their parent.
        subscriber_information: Option<String>,
        claims: RelatedVec<Claim>,
        credential: IssuerCredentialData,
        wallet_instance_attestation_blob_id: Option<BlobId>,
    },
    IssuerBatchParent {
        #[model(nested)]
        common: CredentialCommon,
        issuer: IssuerData,
        webhook_url: Option<String>,
        /// Optional, opaque metadata to allow external clients to store metadata on credentials.
        /// Shared by an entire issuance: batch items read it through their parent.
        subscriber_information: Option<String>,
        claims: RelatedVec<Claim>,
        suspend_end_date: Option<OffsetDateTime>,
        /// Shared by the batch; items read the instance attestation through their parent.
        wallet_instance_attestation_blob_id: Option<BlobId>,
    },
    IssuerBatchItem {
        #[model(nested)]
        common: CredentialCommon,
        issuer: IssuerData,
        parent: Related<Credential>,
        credential: IssuerCredentialData,
    },
    HolderSingle {
        #[model(nested)]
        common: CredentialCommon,
        credential: HolderCredentialData,
    },
    HolderBatchParent {
        #[model(nested)]
        common: CredentialCommon,
    },
    HolderBatchItem {
        #[model(nested)]
        common: CredentialCommon,
        parent: Related<Credential>,
        credential: HolderCredentialData,
        consumed_at: Option<OffsetDateTime>,
    },
    Verifier {
        #[model(nested)]
        common: CredentialCommon,
        verifier_data: VerifierCredentialData,
    },
}

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct CredentialCommon {
    #[model(id)]
    pub id: CredentialId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub issuance_date: Option<OffsetDateTime>,
    pub expires_at: Option<OffsetDateTime>,
    pub protocol: String,
    pub interaction: Option<Related<Interaction>>,
    pub redirect_uri: Option<String>,
    pub profile: Option<String>,
    pub ecosystem: Option<EcosystemId>,
    pub schema: Related<CredentialSchema>,
    pub state: CredentialStateEnum,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct IssuerData {
    pub identifier: Related<Identifier>,
    pub certificate: Option<Related<Certificate>>,
    pub signing_key: Related<Key>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct IssuerCredentialData {
    pub format: Related<CredentialSchemaFormat>,
    pub holder_identifier: Option<Related<Identifier>>,
    pub credential_blob_id: Option<BlobId>,
    pub wallet_key_attestation_blob_id: Option<BlobId>,
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct HolderCredentialData {
    pub issuer: IssuerIdentity,
    pub format: Related<CredentialSchemaFormat>,
    pub claims: RelatedVec<Claim>,
    /// Optional local binding; identifier and key are always supplied together.
    pub binding: Option<HolderBinding>,
    pub credential_blob_id: Option<BlobId>,
    pub embedded_disclosure_policy: Option<String>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct HolderBinding {
    pub identifier: Related<Identifier>,
    pub key: Related<Key>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct VerifierCredentialData {
    pub issuer: IssuerIdentity,
    pub format: Related<CredentialSchemaFormat>,
    pub claims: RelatedVec<Claim>,
    // Optional for legacy reasons only, ISO proximity did not record holder identifiers until v1.88
    pub holder_identifier: Option<Related<Identifier>>,
}

#[derive(Clone, Debug)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub struct IssuerIdentity {
    pub identifier: Related<Identifier>,
    pub certificate: Option<Related<Certificate>>,
}

/// A credential's common fields and one of its variant-specific data groups.
#[derive(Debug)]
pub struct CredentialView<'a, T> {
    pub common: &'a CredentialCommon,
    pub data: &'a T,
}

/// Disjoint mutable borrows of a credential's common fields and a data group.
#[derive(Debug)]
pub struct CredentialViewMut<'a, T> {
    pub common: &'a mut CredentialCommon,
    pub data: &'a mut T,
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialModelError {
    #[error("Expected {expected}, got {actual}")]
    UnexpectedVariant {
        expected: &'static str,
        actual: &'static str,
    },
}

impl ErrorCodeMixin for CredentialModelError {
    fn error_code(&self) -> ErrorCode {
        ErrorCode::BR_0047
    }
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
    /// Issuer identity and signing key, including issuer batch parents.
    pub fn issuer(&self) -> Result<CredentialView<'_, IssuerData>, NestedError> {
        match self {
            Self::IssuerSingle { common, issuer, .. }
            | Self::IssuerBatchParent { common, issuer, .. }
            | Self::IssuerBatchItem { common, issuer, .. } => Ok(CredentialView {
                common,
                data: issuer,
            }),
            other => Err(other.unexpected_variant("an issuer credential")),
        }
    }

    pub fn issuer_mut(&mut self) -> Result<CredentialViewMut<'_, IssuerData>, NestedError> {
        match self {
            Self::IssuerSingle { common, issuer, .. }
            | Self::IssuerBatchParent { common, issuer, .. }
            | Self::IssuerBatchItem { common, issuer, .. } => Ok(CredentialViewMut {
                common,
                data: issuer,
            }),
            other => Err(other.unexpected_variant("an issuer credential")),
        }
    }

    /// Concrete issuer credential data; batch parents have no credential data.
    pub fn issuer_credential(
        &self,
    ) -> Result<CredentialView<'_, IssuerCredentialData>, NestedError> {
        match self {
            Self::IssuerSingle {
                common, credential, ..
            }
            | Self::IssuerBatchItem {
                common, credential, ..
            } => Ok(CredentialView {
                common,
                data: credential,
            }),
            other => Err(other.unexpected_variant("a concrete issuer credential")),
        }
    }

    pub fn issuer_credential_mut(
        &mut self,
    ) -> Result<CredentialViewMut<'_, IssuerCredentialData>, NestedError> {
        match self {
            Self::IssuerSingle {
                common, credential, ..
            }
            | Self::IssuerBatchItem {
                common, credential, ..
            } => Ok(CredentialViewMut {
                common,
                data: credential,
            }),
            other => Err(other.unexpected_variant("a concrete issuer credential")),
        }
    }

    /// Concrete holder credential data; holder batch parents have no credential data.
    pub fn holder(&self) -> Result<CredentialView<'_, HolderCredentialData>, NestedError> {
        match self {
            Self::HolderSingle { common, credential }
            | Self::HolderBatchItem {
                common, credential, ..
            } => Ok(CredentialView {
                common,
                data: credential,
            }),
            other => Err(other.unexpected_variant("a concrete holder credential")),
        }
    }

    pub fn holder_mut(
        &mut self,
    ) -> Result<CredentialViewMut<'_, HolderCredentialData>, NestedError> {
        match self {
            Self::HolderSingle { common, credential }
            | Self::HolderBatchItem {
                common, credential, ..
            } => Ok(CredentialViewMut {
                common,
                data: credential,
            }),
            other => Err(other.unexpected_variant("a concrete holder credential")),
        }
    }

    pub fn verifier(&self) -> Result<CredentialView<'_, VerifierCredentialData>, NestedError> {
        match self {
            Self::Verifier {
                common,
                verifier_data,
            } => Ok(CredentialView {
                common,
                data: verifier_data,
            }),
            other => Err(other.unexpected_variant("a verifier credential")),
        }
    }

    pub fn verifier_mut(
        &mut self,
    ) -> Result<CredentialViewMut<'_, VerifierCredentialData>, NestedError> {
        match self {
            Self::Verifier {
                common,
                verifier_data,
            } => Ok(CredentialViewMut {
                common,
                data: verifier_data,
            }),
            other => Err(other.unexpected_variant("a verifier credential")),
        }
    }

    fn unexpected_variant(&self, expected: &'static str) -> NestedError {
        CredentialModelError::UnexpectedVariant {
            expected,
            actual: self.into(),
        }
        .error_while("accessing credential data")
    }

    pub fn common(&self) -> &CredentialCommon {
        match self {
            Self::IssuerSingle { common, .. }
            | Self::IssuerBatchParent { common, .. }
            | Self::IssuerBatchItem { common, .. }
            | Self::HolderSingle { common, .. }
            | Self::HolderBatchParent { common, .. }
            | Self::HolderBatchItem { common, .. }
            | Self::Verifier { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut CredentialCommon {
        match self {
            Self::IssuerSingle { common, .. }
            | Self::IssuerBatchParent { common, .. }
            | Self::IssuerBatchItem { common, .. }
            | Self::HolderSingle { common, .. }
            | Self::HolderBatchParent { common, .. }
            | Self::HolderBatchItem { common, .. }
            | Self::Verifier { common, .. } => common,
        }
    }

    /// Role used when mapping a credential to an API or storage model.
    pub fn role(&self) -> CredentialRole {
        match self {
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::IssuerBatchItem { .. } => CredentialRole::Issuer,
            Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. } => CredentialRole::Holder,
            Self::Verifier { .. } => CredentialRole::Verifier,
        }
    }

    /// Type used when mapping a credential to an API or storage model.
    pub fn r#type(&self) -> CredentialType {
        match self {
            Self::IssuerSingle { .. } | Self::HolderSingle { .. } | Self::Verifier { .. } => {
                CredentialType::Single
            }
            Self::IssuerBatchParent { .. } | Self::HolderBatchParent { .. } => {
                CredentialType::BatchParent
            }
            Self::IssuerBatchItem { .. } | Self::HolderBatchItem { .. } => {
                CredentialType::BatchItem
            }
        }
    }

    pub fn suspend_end_date(&self) -> Option<OffsetDateTime> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                credential.suspend_end_date
            }
            Self::IssuerBatchParent {
                suspend_end_date, ..
            } => *suspend_end_date,
            Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn format(&self) -> Option<&Related<CredentialSchemaFormat>> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Some(&credential.format)
            }
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Some(&credential.format)
            }
            Self::Verifier { verifier_data, .. } => Some(&verifier_data.format),
            Self::IssuerBatchParent { .. } | Self::HolderBatchParent { .. } => None,
        }
    }

    /// The credential that holds the relevant ecosystem history events.
    /// Points to the batch parent for credentials of type [CredentialType::BatchItem]
    pub(crate) fn ecosystem_history_id(&self) -> CredentialId {
        match self {
            Self::IssuerBatchItem { parent, .. } | Self::HolderBatchItem { parent, .. } => {
                parent.id()
            }
            _ => self.common().id,
        }
    }

    pub(crate) fn is_available_for_presentation(&self, now: OffsetDateTime) -> bool {
        let common = self.common();
        if common.deleted_at.is_some()
            || common.state != CredentialStateEnum::Accepted
            || common.expires_at.is_some_and(|expiry| expiry <= now)
        {
            return false;
        }
        match self {
            Self::HolderSingle { .. } => true,
            Self::HolderBatchItem { consumed_at, .. } => consumed_at.is_none(),
            _ => false,
        }
    }

    /// Returns the concrete credential's format. Batch parents return `None`, even if
    /// they retain a legacy format in storage; use their items' formats instead.
    pub async fn credential_format(&self) -> Result<Option<CredentialFormat>, NestedError> {
        match &self.format() {
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

#[derive(Clone, Debug, PartialEq, Eq)]
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
    /// Failure context for the history event when transitioning to Error.
    /// Consumed by the history decorator; not stored on the credential.
    pub error_info: Option<HistoryErrorMetadata>,
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
