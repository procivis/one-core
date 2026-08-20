use one_core::model::history::{
    HistoryAction, HistoryEntityType, HistorySearchEnum, SortableHistoryColumn,
    TrustResolutionResult,
};
use one_core::service::history::dto::{
    GetHistoryListResponseDTO, TrustResolutionMetadataDTO, WalletRelyingPartyMetadataDTO,
};
use one_dto_mapper::{From, Into, convert_inner};

use super::backup::UnexportableEntitiesBindingDTO;
use super::common::SortDirection;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::into_id;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns the full record for a single history event, including metadata
    /// if present.
    #[uniffi::method]
    pub async fn get_history_entry(
        &self,
        history_id: String,
    ) -> Result<HistoryListItemBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .history_service
            .get_history_entry(into_id(&history_id)?)
            .await?
            .into())
    }

    /// Returns a filterable list of history events.
    #[uniffi::method]
    pub async fn list_history(
        &self,
        query: HistoryListQueryBindingDTO,
    ) -> Result<HistoryListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .history_service
            .get_history_list(query.try_into()?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryAction)]
#[into(HistoryAction)]
#[uniffi(name = "HistoryAction")]
pub enum HistoryActionBindingEnum {
    Accepted,
    Created,
    CsrGenerated,
    Deactivated,
    Deleted,
    Errored,
    Issued,
    Offered,
    Rejected,
    Requested,
    Revoked,
    Suspended,
    Pending,
    Restored,
    Shared,
    Imported,
    ClaimsRemoved,
    Activated,
    Withdrawn,
    Removed,
    Retracted,
    Updated,
    Reactivated,
    Expired,
    InteractionCreated,
    InteractionErrored,
    InteractionExpired,
    Delivered,
    WrpAcReceived,
    WrpRcReceived,
    WrpNrReceived,
    TrustResolved,
    Refreshed,
    Signed,
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(HistoryEntityType)]
#[into(HistoryEntityType)]
#[uniffi(name = "HistoryEntityType")]
pub enum HistoryEntityTypeBindingEnum {
    Key,
    Did,
    Identifier,
    Certificate,
    Credential,
    CredentialSchema,
    Proof,
    ProofSchema,
    Organisation,
    Backup,
    WalletUnit,
    User,
    Provider,
    WalletRelyingParty,
    StsRole,
    StsOrganisation,
    StsIamRole,
    StsSession,
    StsToken,
    Signature,
    Notification,
    SupervisoryAuthority,
    TrustListPublication,
    TrustCollection,
    TrustListSubscription,
    QesDocument,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "HistoryMetadata")]
pub enum HistoryMetadataBinding {
    UnexportableEntities {
        value: UnexportableEntitiesBindingDTO,
    },
    ErrorMetadata {
        value: HistoryErrorMetadataBindingDTO,
    },
    WalletUnitJWT(String),
    WalletRelyingParty {
        value: WalletRelyingPartyMetadataBindingDTO,
    },
    TrustResolution {
        value: TrustResolutionMetadataBindingDTO,
    },
}

#[derive(Debug, Clone, uniffi::Record)]
#[uniffi(name = "MultiLangString")]
pub struct MultiLangStringBindingDTO {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, uniffi::Record)]
#[uniffi(name = "HistoryErrorMetadata")]
pub struct HistoryErrorMetadataBindingDTO {
    pub error_code: String,
    pub message: String,
}

#[derive(Debug, Clone, From, uniffi::Record)]
#[from(WalletRelyingPartyMetadataDTO)]
#[uniffi(name = "WalletRelyingPartyMetadata")]
pub struct WalletRelyingPartyMetadataBindingDTO {
    pub name: Option<String>,
}

#[derive(Debug, Clone, From, uniffi::Record)]
#[from(TrustResolutionMetadataDTO)]
#[uniffi(name = "TrustResolutionMetadata")]
pub struct TrustResolutionMetadataBindingDTO {
    pub result: TrustResolutionResultBindingEnum,
}

#[derive(Debug, Clone, From, uniffi::Enum)]
#[from(TrustResolutionResult)]
#[uniffi(name = "TrustResolutionResult")]
pub enum TrustResolutionResultBindingEnum {
    Trusted,
    Untrusted,
    Unknown,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistoryListItem")]
pub struct HistoryListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub action: HistoryActionBindingEnum,
    /// For credential events, this is the credential schema name. For
    /// presentation events, this is the proof schema name. For all other
    /// entity types, it is the entity name.
    pub name: String,
    pub entity_id: Option<String>,
    pub entity_type: HistoryEntityTypeBindingEnum,
    /// Structured metadata attached to the event. The variant depends on
    /// the type.
    pub metadata: Option<HistoryMetadataBinding>,
    pub organisation_id: Option<String>,
    /// Identifier UUID of the external participant in the interaction, if
    /// applicable. For credential events, this is the counterpart's identifier
    /// (holder when the system is issuer, issuer when the system is holder).
    /// For presentation events, this is the holder's identifier when the system
    /// is verifier, or the verifier's identifier when the system is holder.
    pub target: Option<String>,
    /// Identifier of the user who triggered the event.
    pub user: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableHistoryColumn)]
#[uniffi(name = "SortableHistoryColumn")]
pub enum SortableHistoryColumnBindingEnum {
    CreatedDate,
    Action,
    EntityType,
    Source,
    User,
    OrganisationId,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistoryListQuery")]
pub struct HistoryListQueryBindingDTO {
    /// Page number to retrieve (0-based indexing).
    pub page: u32,
    /// Number of items to return per page.
    pub page_size: u32,
    /// Field value to sort results by.
    pub sort: Option<SortableHistoryColumnBindingEnum>,
    /// Direction to sort results by.
    pub sort_direction: Option<SortDirection>,
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Return only events associated with the provided entity IDs.
    pub entity_ids: Option<Vec<String>>,
    /// Return only events associated with the provided entity types.
    pub entity_types: Option<Vec<HistoryEntityTypeBindingEnum>>,
    /// Return only events of the specified action types.
    pub actions: Option<Vec<HistoryActionBindingEnum>>,
    /// Return only entries created after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_after: Option<String>,
    /// Return only entries created before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_before: Option<String>,
    /// Return only events associated with the provided identifier ID.
    pub identifier_id: Option<String>,
    /// Return only events associated with the provided credential ID.
    pub credential_id: Option<String>,
    /// Return only events associated with the provided credential schema ID.
    pub credential_schema_id: Option<String>,
    /// Return only events associated with the provided proof ID.
    pub proof_id: Option<String>,
    /// Return only events associated with the provided proof schema ID.
    pub proof_schema_id: Option<String>,
    /// Return only events associated with the provided trust collection D.
    pub trust_collection_id: Option<String>,
    /// Search history events by string. Set `text` to specify the search
    /// string and optionally `type` to restrict which field is searched.
    /// When `type` is omitted, all searchable fields are checked.
    pub search: Option<HistorySearchBindingDTO>,
    /// Return only events triggered by the specified users.
    pub users: Option<Vec<String>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetHistoryListResponseDTO)]
#[uniffi(name = "HistoryList")]
pub struct HistoryListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<HistoryListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(HistorySearchEnum)]
#[uniffi(name = "HistorySearchType")]
pub enum HistorySearchTypeBindingEnum {
    All,
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
    IssuerDid,
    IssuerName,
    VerifierDid,
    VerifierName,
    ProofSchemaName,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "HistorySearch")]
pub struct HistorySearchBindingDTO {
    pub text: String,
    /// When omitted, all searchable fields are checked. Set to restrict
    /// the search to a specific field.
    pub r#type: Option<HistorySearchTypeBindingEnum>,
}
