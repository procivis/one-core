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
    pub wallet_instance_attestation_blob_id: Option<BlobId>,
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

    pub fn consumed_at(&self) -> Option<OffsetDateTime> {
        match self {
            Self::HolderBatchItem { consumed_at, .. } => *consumed_at,
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::IssuerBatchItem { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn consumed_at_mut(&mut self) -> Result<&mut Option<OffsetDateTime>, NestedError> {
        match self {
            Self::HolderBatchItem { consumed_at, .. } => Ok(consumed_at),
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::IssuerBatchItem { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

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

    pub fn suspend_end_date_mut(&mut self) -> Result<&mut Option<OffsetDateTime>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.suspend_end_date)
            }
            Self::IssuerBatchParent {
                suspend_end_date, ..
            } => Ok(suspend_end_date),
            Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn credential_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                credential.credential_blob_id
            }
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                credential.credential_blob_id
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn credential_blob_id_mut(&mut self) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.credential_blob_id)
            }
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&mut credential.credential_blob_id)
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn wallet_key_attestation_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                credential.wallet_key_attestation_blob_id
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn wallet_key_attestation_blob_id_mut(
        &mut self,
    ) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.wallet_key_attestation_blob_id)
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn wallet_instance_attestation_blob_id(&self) -> Option<BlobId> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                credential.wallet_instance_attestation_blob_id
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn wallet_instance_attestation_blob_id_mut(
        &mut self,
    ) -> Result<&mut Option<BlobId>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.wallet_instance_attestation_blob_id)
            }
            Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn webhook_url(&self) -> &Option<String> {
        match self {
            Self::IssuerSingle { webhook_url, .. }
            | Self::IssuerBatchParent { webhook_url, .. } => webhook_url,
            Self::IssuerBatchItem { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => &None,
        }
    }

    pub fn webhook_url_mut(&mut self) -> Result<&mut Option<String>, NestedError> {
        match self {
            Self::IssuerSingle { webhook_url, .. }
            | Self::IssuerBatchParent { webhook_url, .. } => Ok(webhook_url),
            Self::IssuerBatchItem { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn embedded_disclosure_policy(&self) -> &Option<String> {
        match self {
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                &credential.embedded_disclosure_policy
            }
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::IssuerBatchItem { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => &None,
        }
    }

    pub fn embedded_disclosure_policy_mut(&mut self) -> Result<&mut Option<String>, NestedError> {
        match self {
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&mut credential.embedded_disclosure_policy)
            }
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::IssuerBatchItem { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn subscriber_information(&self) -> &Option<String> {
        match self {
            Self::IssuerSingle {
                subscriber_information,
                ..
            }
            | Self::IssuerBatchParent {
                subscriber_information,
                ..
            } => subscriber_information,
            Self::IssuerBatchItem { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. }
            | Self::Verifier { .. } => &None,
        }
    }

    /// Locally owned claims. Issuer batch items inherit claims; holder batch parents own none.
    pub fn claims(&self) -> Result<&RelatedVec<Claim>, NestedError> {
        match self {
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&credential.claims)
            }
            Self::IssuerSingle { claims, .. } | Self::IssuerBatchParent { claims, .. } => {
                Ok(claims)
            }
            Self::Verifier { verifier_data, .. } => Ok(&verifier_data.claims),
            Self::IssuerBatchItem { .. } | Self::HolderBatchParent { .. } => {
                Err(DataLayerError::MappingError
                    .error_while("accessing a field unavailable on this credential variant"))
            }
        }
    }

    pub fn claims_mut(&mut self) -> Result<&mut RelatedVec<Claim>, NestedError> {
        match self {
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&mut credential.claims)
            }
            Self::IssuerSingle { claims, .. } | Self::IssuerBatchParent { claims, .. } => {
                Ok(claims)
            }
            Self::Verifier { verifier_data, .. } => Ok(&mut verifier_data.claims),
            Self::IssuerBatchItem { .. } | Self::HolderBatchParent { .. } => {
                Err(DataLayerError::MappingError
                    .error_while("accessing a field unavailable on this credential variant"))
            }
        }
    }

    pub fn issuer_identifier(&self) -> Option<&Related<Identifier>> {
        match self {
            Self::IssuerSingle { issuer, .. }
            | Self::IssuerBatchParent { issuer, .. }
            | Self::IssuerBatchItem { issuer, .. } => Some(&issuer.identifier),
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Some(&credential.issuer.identifier)
            }
            Self::Verifier { verifier_data, .. } => Some(&verifier_data.issuer.identifier),
            Self::HolderBatchParent { .. } => None,
        }
    }

    pub fn issuer_certificate(&self) -> &Option<Related<Certificate>> {
        match self {
            Self::IssuerSingle { issuer, .. }
            | Self::IssuerBatchParent { issuer, .. }
            | Self::IssuerBatchItem { issuer, .. } => &issuer.certificate,
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                &credential.issuer.certificate
            }
            Self::Verifier { verifier_data, .. } => &verifier_data.issuer.certificate,
            Self::HolderBatchParent { .. } => &None,
        }
    }

    pub fn issuer_certificate_mut(
        &mut self,
    ) -> Result<&mut Option<Related<Certificate>>, NestedError> {
        match self {
            Self::IssuerSingle { issuer, .. }
            | Self::IssuerBatchParent { issuer, .. }
            | Self::IssuerBatchItem { issuer, .. } => Ok(&mut issuer.certificate),
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&mut credential.issuer.certificate)
            }
            Self::Verifier { verifier_data, .. } => Ok(&mut verifier_data.issuer.certificate),
            Self::HolderBatchParent { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }

    pub fn holder_identifier(&self) -> Option<&Related<Identifier>> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                credential.holder_identifier.as_ref()
            }
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                credential
                    .binding
                    .as_ref()
                    .map(|binding| &binding.identifier)
            }
            Self::Verifier { verifier_data, .. } => verifier_data.holder_identifier.as_ref(),
            Self::IssuerBatchParent { .. } | Self::HolderBatchParent { .. } => None,
        }
    }

    pub fn holder_identifier_mut(
        &mut self,
    ) -> Result<&mut Option<Related<Identifier>>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.holder_identifier)
            }
            Self::Verifier { verifier_data, .. } => Ok(&mut verifier_data.holder_identifier),
            Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::HolderBatchItem { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
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

    pub fn format_mut(&mut self) -> Result<&mut Related<CredentialSchemaFormat>, NestedError> {
        match self {
            Self::IssuerSingle { credential, .. } | Self::IssuerBatchItem { credential, .. } => {
                Ok(&mut credential.format)
            }
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                Ok(&mut credential.format)
            }
            Self::Verifier { verifier_data, .. } => Ok(&mut verifier_data.format),
            Self::IssuerBatchParent { .. } | Self::HolderBatchParent { .. } => {
                Err(DataLayerError::MappingError
                    .error_while("accessing a field unavailable on this credential variant"))
            }
        }
    }

    pub fn key(&self) -> Option<&Related<Key>> {
        match self {
            Self::IssuerSingle { issuer, .. }
            | Self::IssuerBatchParent { issuer, .. }
            | Self::IssuerBatchItem { issuer, .. } => Some(&issuer.signing_key),
            Self::HolderSingle { credential, .. } | Self::HolderBatchItem { credential, .. } => {
                credential.binding.as_ref().map(|binding| &binding.key)
            }
            Self::HolderBatchParent { .. } | Self::Verifier { .. } => None,
        }
    }

    pub fn parent(&self) -> Option<&Related<Credential>> {
        match self {
            Self::IssuerBatchItem { parent, .. } | Self::HolderBatchItem { parent, .. } => {
                Some(parent)
            }
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => None,
        }
    }

    pub fn parent_mut(&mut self) -> Result<&mut Related<Credential>, NestedError> {
        match self {
            Self::IssuerBatchItem { parent, .. } | Self::HolderBatchItem { parent, .. } => {
                Ok(parent)
            }
            Self::IssuerSingle { .. }
            | Self::IssuerBatchParent { .. }
            | Self::HolderSingle { .. }
            | Self::HolderBatchParent { .. }
            | Self::Verifier { .. } => Err(DataLayerError::MappingError
                .error_while("accessing a field unavailable on this credential variant")),
        }
    }
    /// The credential that holds the relevant ecosystem history events.
    /// Points to the batch parent for credentials of type [CredentialType::BatchItem]
    pub(crate) fn ecosystem_history_id(&self) -> CredentialId {
        self.parent()
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
