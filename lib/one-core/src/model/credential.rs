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
use crate::error::{ErrorCodeMixinExt, NestedError};
use crate::model::certificate::Certificate;
use crate::model::credential_schema_format::CredentialSchemaFormat;
use crate::model::history::HistoryErrorMetadata;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::relation::{Related, RelatedVec};
use crate::repository::error::DataLayerError;

#[derive(Clone, Debug, Model)]
#[cfg_attr(any(test, feature = "mock"), derive(PartialEq))]
pub enum Credential {
    /// TODO ONE-11429: Temporary shim until the credential model has been fully refactored into
    /// role and type specific variants.
    Generic {
        #[model(nested)]
        common: CredentialCommon,
        consumed_at: Option<OffsetDateTime>,
        role: CredentialRole,
        r#type: CredentialType,
        suspend_end_date: Option<OffsetDateTime>,
        credential_blob_id: Option<BlobId>,
        wallet_key_attestation_blob_id: Option<BlobId>,
        wallet_instance_attestation_blob_id: Option<BlobId>,
        webhook_url: Option<String>,
        /// Holder configuration policy, stored on singles and batch items, not batch parents.
        embedded_disclosure_policy: Option<String>,
        subscriber_information: Option<String>,

        // Relations:
        claims: RelatedVec<Claim>,
        issuer_identifier: Option<Related<Identifier>>,
        issuer_certificate: Option<Related<Certificate>>,
        holder_identifier: Option<Related<Identifier>>,
        format: Option<Related<CredentialSchemaFormat>>,
        key: Option<Related<Key>>,
        parent: Option<Related<Credential>>,
    },
    IssuerSingle {
        #[model(nested)]
        common: CredentialCommon,
        issuer: IssuerData,
        suspend_end_date: Option<OffsetDateTime>,
        webhook_url: Option<String>,
        /// Optional, opaque metadata to allow external clients to store metadata on credentials.
        /// Shared by an entire issuance: batch items read it through their parent.
        subscriber_information: Option<String>,
        claims: RelatedVec<Claim>,
        credential: IssuerCredentialData,
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
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
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
    pub fn common(&self) -> &CredentialCommon {
        match self {
            Self::Generic { common, .. }
            | Self::IssuerSingle { common, .. }
            | Self::Verifier { common, .. } => common,
        }
    }

    pub fn common_mut(&mut self) -> &mut CredentialCommon {
        match self {
            Self::Generic { common, .. }
            | Self::IssuerSingle { common, .. }
            | Self::Verifier { common, .. } => common,
        }
    }

    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Generic { consumed_at, .. } => *consumed_at,
            Self::IssuerSingle { .. } | Self::Verifier { .. } => None,
        }
    }

    pub fn consumed_at_mut(&mut self) -> Result<&mut Option<OffsetDateTime>, NestedError> {
        match self {
            Self::Generic { consumed_at, .. } => Ok(consumed_at),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn role(&self) -> CredentialRole {
        match self {
            Self::Generic { role, .. } => *role,
            Self::IssuerSingle { .. } => CredentialRole::Issuer,
            Self::Verifier { .. } => CredentialRole::Verifier,
        }
    }

    pub fn role_mut(&mut self) -> Result<&mut CredentialRole, NestedError> {
        match self {
            Self::Generic { role, .. } => Ok(role),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn r#type(&self) -> CredentialType {
        match self {
            Self::Generic { r#type, .. } => *r#type,
            Self::IssuerSingle { .. } | Self::Verifier { .. } => CredentialType::Single,
        }
    }

    pub fn type_mut(&mut self) -> Result<&mut CredentialType, NestedError> {
        match self {
            Self::Generic { r#type, .. } => Ok(r#type),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn suspend_end_date(&self) -> Option<OffsetDateTime> {
        match self {
            Self::Generic {
                suspend_end_date, ..
            }
            | Self::IssuerSingle {
                suspend_end_date, ..
            } => *suspend_end_date,
            Self::Verifier { .. } => None,
        }
    }

    pub fn suspend_end_date_mut(&mut self) -> Result<&mut Option<OffsetDateTime>, NestedError> {
        match self {
            Self::Generic {
                suspend_end_date, ..
            }
            | Self::IssuerSingle {
                suspend_end_date, ..
            } => Ok(suspend_end_date),
            Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on a verifier credential")),
        }
    }

    pub fn credential_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::Generic {
                credential_blob_id, ..
            } => *credential_blob_id,
            Self::IssuerSingle { credential, .. } => credential.credential_blob_id,
            Self::Verifier { .. } => None,
        }
    }

    pub fn credential_blob_id_mut(&mut self) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::Generic {
                credential_blob_id, ..
            } => Ok(credential_blob_id),
            Self::IssuerSingle { credential, .. } => Ok(&mut credential.credential_blob_id),
            Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on a verifier credential")),
        }
    }

    pub fn wallet_key_attestation_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::Generic {
                wallet_key_attestation_blob_id,
                ..
            } => *wallet_key_attestation_blob_id,
            Self::IssuerSingle { credential, .. } => credential.wallet_key_attestation_blob_id,
            Self::Verifier { .. } => None,
        }
    }

    pub fn wallet_key_attestation_blob_id_mut(
        &mut self,
    ) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::Generic {
                wallet_key_attestation_blob_id,
                ..
            } => Ok(wallet_key_attestation_blob_id),
            Self::IssuerSingle { credential, .. } => {
                Ok(&mut credential.wallet_key_attestation_blob_id)
            }
            Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on a verifier credential")),
        }
    }

    pub fn wallet_instance_attestation_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::Generic {
                wallet_instance_attestation_blob_id,
                ..
            } => *wallet_instance_attestation_blob_id,
            Self::IssuerSingle { credential, .. } => credential.wallet_instance_attestation_blob_id,
            Self::Verifier { .. } => None,
        }
    }

    pub fn wallet_instance_attestation_blob_id_mut(
        &mut self,
    ) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::Generic {
                wallet_instance_attestation_blob_id,
                ..
            } => Ok(wallet_instance_attestation_blob_id),
            Self::IssuerSingle { credential, .. } => {
                Ok(&mut credential.wallet_instance_attestation_blob_id)
            }
            Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on a verifier credential")),
        }
    }

    pub fn webhook_url(&self) -> &Option<String> {
        match self {
            Self::Generic { webhook_url, .. } | Self::IssuerSingle { webhook_url, .. } => {
                webhook_url
            }
            Self::Verifier { .. } => &None,
        }
    }

    pub fn webhook_url_mut(&mut self) -> Result<&mut Option<String>, NestedError> {
        match self {
            Self::Generic { webhook_url, .. } | Self::IssuerSingle { webhook_url, .. } => {
                Ok(webhook_url)
            }
            Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on a verifier credential")),
        }
    }

    pub fn embedded_disclosure_policy(&self) -> &Option<String> {
        match self {
            Self::Generic {
                embedded_disclosure_policy,
                ..
            } => embedded_disclosure_policy,
            Self::IssuerSingle { .. } | Self::Verifier { .. } => &None,
        }
    }

    pub fn embedded_disclosure_policy_mut(&mut self) -> Result<&mut Option<String>, NestedError> {
        match self {
            Self::Generic {
                embedded_disclosure_policy,
                ..
            } => Ok(embedded_disclosure_policy),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn subscriber_information(&self) -> &Option<String> {
        match self {
            Self::Generic {
                subscriber_information,
                ..
            }
            | Self::IssuerSingle {
                subscriber_information,
                ..
            } => subscriber_information,
            Self::Verifier { .. } => &None,
        }
    }

    pub fn claims(&self) -> &RelatedVec<Claim> {
        match self {
            Self::Generic { claims, .. } | Self::IssuerSingle { claims, .. } => claims,
            Self::Verifier { verifier_data, .. } => &verifier_data.claims,
        }
    }

    pub fn claims_mut(&mut self) -> &mut RelatedVec<Claim> {
        match self {
            Self::Generic { claims, .. } | Self::IssuerSingle { claims, .. } => claims,
            Self::Verifier { verifier_data, .. } => &mut verifier_data.claims,
        }
    }

    pub fn issuer_identifier(&self) -> Option<&Related<Identifier>> {
        match self {
            Self::Generic {
                issuer_identifier, ..
            } => issuer_identifier.as_ref(),
            Self::IssuerSingle { issuer, .. } => Some(&issuer.identifier),
            Self::Verifier { verifier_data, .. } => Some(&verifier_data.issuer.identifier),
        }
    }

    pub fn issuer_identifier_mut(
        &mut self,
    ) -> Result<&mut Option<Related<Identifier>>, NestedError> {
        match self {
            Self::Generic {
                issuer_identifier, ..
            } => Ok(issuer_identifier),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn issuer_certificate(&self) -> &Option<Related<Certificate>> {
        match self {
            Self::Generic {
                issuer_certificate, ..
            } => issuer_certificate,
            Self::IssuerSingle { issuer, .. } => &issuer.certificate,
            Self::Verifier { verifier_data, .. } => &verifier_data.issuer.certificate,
        }
    }

    pub fn issuer_certificate_mut(&mut self) -> &mut Option<Related<Certificate>> {
        match self {
            Self::Generic {
                issuer_certificate, ..
            } => issuer_certificate,
            Self::IssuerSingle { issuer, .. } => &mut issuer.certificate,
            Self::Verifier { verifier_data, .. } => &mut verifier_data.issuer.certificate,
        }
    }

    pub fn holder_identifier(&self) -> &Option<Related<Identifier>> {
        match self {
            Self::Generic {
                holder_identifier, ..
            } => holder_identifier,
            Self::IssuerSingle { credential, .. } => &credential.holder_identifier,
            Self::Verifier { verifier_data, .. } => &verifier_data.holder_identifier,
        }
    }

    pub fn holder_identifier_mut(&mut self) -> &mut Option<Related<Identifier>> {
        match self {
            Self::Generic {
                holder_identifier, ..
            } => holder_identifier,
            Self::IssuerSingle { credential, .. } => &mut credential.holder_identifier,
            Self::Verifier { verifier_data, .. } => &mut verifier_data.holder_identifier,
        }
    }

    pub fn format(&self) -> Option<&Related<CredentialSchemaFormat>> {
        match self {
            Self::Generic { format, .. } => format.as_ref(),
            Self::IssuerSingle { credential, .. } => Some(&credential.format),
            Self::Verifier { verifier_data, .. } => Some(&verifier_data.format),
        }
    }

    pub fn format_mut(
        &mut self,
    ) -> Result<&mut Option<Related<CredentialSchemaFormat>>, NestedError> {
        match self {
            Self::Generic { format, .. } => Ok(format),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn key(&self) -> Option<&Related<Key>> {
        match self {
            Self::Generic { key, .. } => key.as_ref(),
            Self::IssuerSingle { issuer, .. } => Some(&issuer.signing_key),
            Self::Verifier { .. } => None,
        }
    }

    pub fn key_mut(&mut self) -> Result<&mut Option<Related<Key>>, NestedError> {
        match self {
            Self::Generic { key, .. } => Ok(key),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn parent(&self) -> &Option<Related<Credential>> {
        match self {
            Self::Generic { parent, .. } => parent,
            Self::IssuerSingle { .. } | Self::Verifier { .. } => &None,
        }
    }

    pub fn parent_mut(&mut self) -> Result<&mut Option<Related<Credential>>, NestedError> {
        match self {
            Self::Generic { parent, .. } => Ok(parent),
            Self::IssuerSingle { .. } | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    /// The credential that holds the relevant ecosystem history events.
    /// Points to the batch parent for credentials of type [CredentialType::BatchItem]
    pub(crate) fn ecosystem_history_id(&self) -> CredentialId {
        self.parent()
            .as_ref()
            .map(|parent| parent.id())
            .unwrap_or(self.common().id)
    }

    pub(crate) fn is_available_for_presentation(&self, now: OffsetDateTime) -> bool {
        if self.common().deleted_at.is_some()
            || self.common().state != CredentialStateEnum::Accepted
        {
            return false;
        }
        match self.r#type() {
            CredentialType::Single => true,
            CredentialType::BatchParent => false,
            CredentialType::BatchItem => {
                self.consumed_at().is_none()
                    && self.common().expires_at.is_none_or(|expiry| expiry > now)
            }
        }
    }

    /// Returns the concrete credential's format. Batch parents return `None`, even if
    /// they retain a legacy format in storage; use their items' formats instead.
    pub async fn credential_format(&self) -> Result<Option<CredentialFormat>, NestedError> {
        if self.r#type() == CredentialType::BatchParent {
            return Ok(None);
        }
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
