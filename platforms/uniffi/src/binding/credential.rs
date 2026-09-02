use one_core::model::credential::{
    CredentialListIncludeEntityTypeEnum, ExactCredentialFilterColumn, SortableCredentialColumn,
};
use one_core::service::credential::dto::{
    CredentialRole, CredentialSearchTypeDTO, CredentialStateEnum, CredentialTypeEnum,
    DetailCredentialClaimResponseDTO, GetCredentialListResponseDTO, TrustInformation,
};
use one_core::service::credential_schema::dto::CredentialClaimSchemaDTO;
use one_dto_mapper::{From, Into, convert_inner};

use super::common::SortDirection;
use super::identifier::GetIdentifierListItemBindingDTO;
use crate::OneCore;
use crate::binding::credential_schema::{
    CredentialClaimSchemaTranslationsBindingDTO, CredentialSchemaLayoutPropertiesBindingDTO,
    CredentialSchemaListItemV2BindingDTO, CredentialSchemaTranslationsBindingDTO,
    KeyStorageSecurityBindingEnum,
};
use crate::binding::history::TrustResolutionResultBindingEnum;
use crate::binding::trust_information::TrustInformationDetailResponseBindingDTO;
use crate::error::BindingError;
use crate::utils::{TimestampFormat, into_id};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns detailed information about a credential in the system.
    #[uniffi::method]
    pub async fn get_credential(
        &self,
        credential_id: String,
    ) -> Result<CredentialDetailBindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .credential_service
            .get_credential(&into_id(&credential_id)?)
            .await?
            .into())
    }

    /// Returns detailed trust information about a credential issuer.
    #[uniffi::method]
    pub async fn get_credential_trust_information(
        &self,
        credential_id: String,
    ) -> Result<TrustInformationDetailResponseBindingDTO, BindingError> {
        let core = self.use_core().await?;
        let trust_information = core
            .credential_service
            .get_trust_details(into_id(&credential_id)?)
            .await?;
        Ok(trust_information.into())
    }

    /// Returns a filterable list of credentials in the system.
    #[uniffi::method]
    pub async fn list_credentials(
        &self,
        query: CredentialListQueryBindingDTO,
    ) -> Result<CredentialListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .credential_service
            .get_credential_list(query.try_into()?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn delete_credential(&self, credential_id: String) -> Result<(), BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .credential_service
            .delete_credential(&into_id(&credential_id)?)
            .await?)
    }
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialSchemaInfo")]
pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    pub translations: Option<CredentialSchemaTranslationsBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialDetail")]
pub struct CredentialDetailBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub expires_at: Option<String>,
    /// Credential issuer metadata.
    pub issuer: Option<GetIdentifierListItemBindingDTO>,
    /// Credential holder metadata.
    pub holder: Option<GetIdentifierListItemBindingDTO>,
    /// State representation of the credential in the system.
    pub state: CredentialStateBindingEnum,
    /// Schema of the credential.
    pub schema: CredentialSchemaListItemV2BindingDTO,
    pub claims: Vec<ClaimBindingDTO>,
    pub redirect_uri: Option<String>,
    /// The role the system has in relation to the credential. For example,
    /// if the system received the credential as a wallet this value will
    /// be `HOLDER`. If the system verified this credential during a presentation,
    /// this value will be `VERIFIER`.
    pub role: CredentialRoleBindingDTO,
    pub interaction_id: Option<String>,
    /// Scheduled date for credential reactivation.
    pub suspend_end_date: Option<String>,
    /// Validity details for ISO mdocs.
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseBindingDTO>,
    /// Protocol used to issue the credential.
    pub protocol: String,
    /// Country profile associated with the credential.
    pub profile: Option<String>,
    pub trust_information: Option<TrustInformationBindingDTO>,

    pub consumed_at: Option<String>,
    pub r#type: CredentialTypeBindingEnum,
    pub remaining_batch_item_count: Option<u32>,
    pub parent_id: Option<String>,
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(TrustInformation)]
#[uniffi(name = "TrustInformation")]
pub struct TrustInformationBindingDTO {
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    received_at: String,
    name: Option<String>,
    result: TrustResolutionResultBindingEnum,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactCredentialFilterColumn)]
#[uniffi(name = "CredentialListQueryExactColumn")]
pub enum CredentialListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialColumn)]
#[uniffi(name = "SortableCredentialColumn")]
pub enum SortableCredentialColumnBindingEnum {
    CreatedDate,
    SchemaName,
    Issuer,
    State,
    ExpiresAt,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialSearchTypeDTO)]
#[uniffi(name = "CredentialListQuerySearchType")]
pub enum SearchTypeBindingEnum {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialListQuery")]
pub struct CredentialListQueryBindingDTO {
    /// Page number to retrieve (0-based indexing).
    pub page: u32,
    /// Number of items to return per page.
    pub page_size: u32,
    /// Field value to sort results by.
    pub sort: Option<SortableCredentialColumnBindingEnum>,
    /// Direction to sort results by.
    pub sort_direction: Option<SortDirection>,
    /// Specifies the organizational context for this operation.
    pub organisation_id: String,
    /// Return only credentials with a name starting with this string.
    pub name: Option<String>,
    /// Filter by one or more country profiles.
    pub profiles: Option<Vec<String>>,
    /// Search for a string.
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. Choose one or more
    /// `searchType`s and pass a `searchText`.
    pub search_type: Option<Vec<SearchTypeBindingEnum>>,
    /// Set which filters apply in an exact way.
    pub exact: Option<Vec<CredentialListQueryExactColumnBindingEnum>>,
    /// Filter credentials by one or more roles: issued by the system,
    /// verified by the system, or held by the system as a wallet.
    pub roles: Option<Vec<CredentialRoleBindingDTO>>,
    /// Filter by one or more UUIDs.
    pub ids: Option<Vec<String>>,
    /// Filter by batch parent UUID.
    pub parent_id: Option<String>,
    /// Filter by one or more credential states.
    pub states: Option<Vec<CredentialStateBindingEnum>>,
    /// Filter by one or more credential types.
    pub types: Option<Vec<CredentialTypeBindingEnum>>,
    /// Additional fields to include in response objects. Omitting
    /// this keeps responses shorter.
    pub include: Option<Vec<CredentialListIncludeEntityTypeBindingEnum>>,
    /// Return only credentials with the specified credential schema(s).
    pub credential_schema_ids: Option<Vec<String>>,
    pub ecosystems: Option<Vec<String>>,

    /// Return only credentials created after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_after: Option<String>,
    /// Return only credentials created before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub created_date_before: Option<String>,
    /// Return only credentials last modified after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_after: Option<String>,
    /// Return only credentials last modified before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub last_modified_before: Option<String>,
    /// Return only credentials issued after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub issuance_date_after: Option<String>,
    /// Return only credentials issued before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub issuance_date_before: Option<String>,
    /// Return only credentials revoked after this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub revocation_date_after: Option<String>,
    /// Return only credentials revoked before this time. Timestamp in
    /// RFC 3339 format (for example `2023-06-09T14:19:57.000Z`).
    pub revocation_date_before: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialListIncludeEntityTypeEnum)]
#[uniffi(name = "CredentialListIncludeEntityType")]
pub enum CredentialListIncludeEntityTypeBindingEnum {
    LayoutProperties,
    Translations,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialListResponseDTO)]
#[uniffi(name = "CredentialList")]
pub struct CredentialListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "MdocMsoValidity")]
pub struct MdocMsoValidityResponseBindingDTO {
    pub expiration: String,
    pub next_update: String,
    pub last_update: String,
}

#[derive(Clone, Debug, From, Into, Eq, PartialEq, uniffi::Enum)]
#[from(CredentialStateEnum)]
#[into(CredentialStateEnum)]
#[uniffi(name = "CredentialState")]
pub enum CredentialStateBindingEnum {
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
    Expiring,
}

#[derive(Clone, Debug, From, Into, Eq, PartialEq, uniffi::Enum)]
#[from(CredentialTypeEnum)]
#[into(CredentialTypeEnum)]
#[uniffi(name = "CredentialType")]
pub enum CredentialTypeBindingEnum {
    Single,
    BatchParent,
    BatchItem,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialClaimSchemaDTO)]
#[uniffi(name = "ClaimSchemaInfo")]
pub struct CredentialClaimSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
    pub translations: CredentialClaimSchemaTranslationsBindingDTO,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(DetailCredentialClaimResponseDTO)]
#[uniffi(name = "Claim")]
pub struct ClaimBindingDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaBindingDTO,
    pub value: ClaimValueBindingDTO,
}

#[derive(Clone, Debug, uniffi::Enum)]
#[uniffi(name = "ClaimValue")]
pub enum ClaimValueBindingDTO {
    Boolean { value: bool },
    Float { value: f64 },
    Integer { value: i64 },
    String { value: String },
    Nested { value: Vec<ClaimBindingDTO> },
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[from(CredentialRole)]
#[into(CredentialRole)]
#[uniffi(name = "CredentialRole")]
pub enum CredentialRoleBindingDTO {
    Holder,
    Issuer,
    Verifier,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialListItem")]
pub struct CredentialListItemBindingDTO {
    pub id: String,
    pub created_date: String,
    pub issuance_date: Option<String>,
    pub last_modified: String,
    pub revocation_date: Option<String>,
    pub expires_at: Option<String>,
    /// Credential issuer metadata.
    pub issuer: Option<String>,
    /// State representation of the credential in the system.
    pub state: CredentialStateBindingEnum,
    /// Schema of the credential.
    pub schema: CredentialSchemaListItemV2BindingDTO,
    /// The role the system has in relation to the credential. For example,
    /// if the system received the credential as a wallet this value will
    /// be `HOLDER`. If the system verified this credential during a presentation,
    /// this value will be `VERIFIER`.
    pub role: CredentialRoleBindingDTO,
    /// Scheduled date for credential reactivation.
    pub suspend_end_date: Option<String>,
    /// Protocol used to issue the credential.
    pub protocol: String,
    /// Country profile associated with the credential.
    pub profile: Option<String>,

    pub consumed_at: Option<String>,
    pub r#type: CredentialTypeBindingEnum,
    pub parent_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub ecosystem: Option<String>,
}
