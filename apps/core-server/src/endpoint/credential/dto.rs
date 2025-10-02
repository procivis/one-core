use one_core::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialListIncludeEntityTypeEnum, CredentialListItemResponseDTO,
    CredentialRequestClaimDTO, CredentialRevocationCheckResponseDTO, CredentialRole,
    CredentialStateEnum, DetailCredentialClaimResponseDTO, DetailCredentialClaimValueResponseDTO,
    DetailCredentialSchemaResponseDTO, MdocMsoValidityResponseDTO, SuspendCredentialRequestDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId, OrganisationId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::credential_schema::dto::{
    CredentialClaimSchemaResponseRestDTO, CredentialSchemaLayoutPropertiesRestDTO,
    CredentialSchemaLayoutType, CredentialSchemaListItemResponseRestDTO, CredentialSchemaType,
    WalletStorageTypeRestEnum,
};
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialListItemResponseDTO)]
pub(crate) struct CredentialListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub schema: CredentialSchemaListItemResponseRestDTO,
    #[from(with_fn = convert_inner)]
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,
    pub role: CredentialRoleRestEnum,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub protocol: String,
    /// Profile associated with this credential
    #[from(with_fn = convert_inner)]
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(MdocMsoValidityResponseDTO)]
pub(crate) struct MdocMsoValidityResponseRestDTO {
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub expiration: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub next_update: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_update: OffsetDateTime,
}

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GetCredentialResponseRestDTO<T> {
    pub id: Uuid,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: Option<OffsetDateTime>,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,

    pub schema: CredentialDetailSchemaResponseRestDTO,

    /// Identifier ID of the issuer.
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,

    /// Certificate details if issuer is using an X.509.
    pub issuer_certificate: Option<CertificateResponseRestDTO>,

    /// Claims made by issuer. During the credential offer phase this
    /// will be empty unless the issuer has provided preview values.
    pub claims: Vec<T>,

    pub redirect_uri: Option<String>,

    /// The role the system has in relation to the credential.
    pub role: CredentialRoleRestEnum,

    /// When the current LVVC was issued.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseRestDTO>,
    pub holder: Option<GetIdentifierListItemResponseRestDTO>,
    pub protocol: String,
    /// Profile associated with this credential
    pub profile: Option<String>,
}

/// The role the system has in relation to the credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[from(CredentialRole)]
#[into(CredentialRole)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CredentialRoleRestEnum {
    Holder,
    Issuer,
    Verifier,
}

/// Credential schema being used to issue the credential.
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialSchemaResponseDTO)]
pub(crate) struct CredentialDetailSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: OrganisationId,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// Part of the `credentialSchema` property.
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialClaimResponseDTO)]
pub(crate) struct CredentialDetailClaimResponseRestDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaResponseRestDTO,
    pub value: CredentialDetailClaimValueResponseRestDTO,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(DetailCredentialClaimValueResponseDTO)]
#[serde(untagged)]
pub(crate) enum CredentialDetailClaimValueResponseRestDTO {
    Boolean(bool),
    Float(f64),
    Integer(i64),
    String(String),
    #[schema(no_recursion)]
    Nested(#[from(with_fn = convert_inner)] Vec<CredentialDetailClaimResponseRestDTO>),
}

/// The state represenation of the credential in the system.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CredentialStateEnum)]
#[into(one_core::model::credential::CredentialStateEnum)]
pub(crate) enum CredentialStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Suspended,
    Rejected,
    Revoked,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SearchType {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialsFilterQueryParamsRest {
    /// Specify the organization from which to return credentials.
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only credentials with a name starting with this string.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Return only credentials with the specified profile.
    #[param(nullable = false)]
    pub profile: Option<String>,
    /// Filter credentials by whether they were issued by the system,
    /// verified by the system or are held by the system as with a wallet.
    #[param(nullable = false)]
    pub role: Option<CredentialRoleRestEnum>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    /// Filter by specific UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialId>>,
    /// Return only credentials with the specified credential state.
    #[param(rename = "status[]", inline, nullable = false)]
    pub status: Option<Vec<CredentialStateRestEnum>>,
    /// Search for a string.
    #[param(nullable = false)]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. To search credentials,
    /// choose one or more `searchType`s and pass a `searchText`.
    #[param(rename = "searchType[]", inline, nullable = false)]
    pub search_type: Option<Vec<SearchType>>,

    #[param(rename = "credentialSchemaIds[]", inline, nullable = false)]
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,

    /// Return only credentials which were created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credentials which were created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credentials which were last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credentials which were last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// Return only credentials which were issued after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub issuance_date_after: Option<OffsetDateTime>,
    /// Return only credentials which were issued before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub issuance_date_before: Option<OffsetDateTime>,
    /// Return only credentials which were revoked after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub revocation_date_after: Option<OffsetDateTime>,
    /// Return only credentials which were revoked before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub revocation_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialListIncludeEntityTypeEnum)]
pub(crate) enum CredentialListIncludeEntityTypeRestEnum {
    LayoutProperties,
}

pub(crate) type GetCredentialQuery = ListQueryParamsRest<
    CredentialsFilterQueryParamsRest,
    SortableCredentialColumnRestEnum,
    CredentialListIncludeEntityTypeRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential::SortableCredentialColumn")]
pub(crate) enum SortableCredentialColumnRestEnum {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    Issuer,
    State,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into, ModifySchema)]
#[into(CreateCredentialRequestDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreateCredentialRequestRestDTO {
    /// UUID of the credential schema to use for this credential. The `id`
    /// field is returned when creating a credential schema; do not use the
    /// `schemaId` (document type) value.
    pub credential_schema_id: CredentialSchemaId,
    /// UUID of the identifier to use for issuing this credential. This
    /// references an identifier entry (which could be a DID, key, or certificate)
    /// created via the identifiers API. Use the `id` field from the identifier,
    /// not the actual DID string or key value.
    pub issuer: Option<IdentifierId>,
    #[schema(deprecated = true)]
    /// Deprecated. Use `issuer` to set the identifier, regardless of type.
    pub issuer_did: Option<DidId>,
    /// If multiple keys are specified for the assertion method of the DID,
    /// use this value to specify which key should be used as the assertion
    /// method for this credential. If a key isn't specified here, the first
    /// key listed during DID creation will be used.
    #[into(with_fn = convert_inner)]
    pub issuer_key: Option<KeyId>,
    /// If multiple active certificates are available under the issuer,
    /// use this value to specify which certificate should be used
    /// for this credential. If a certificate isn't specified here,
    /// an active certificate will be used.
    #[schema(nullable = false)]
    pub issuer_certificate: Option<CertificateId>,
    /// Issuance protocol to use for issuing the credential to a wallet. Check
    /// your `issuanceProtocol` configuration for supported options and
    /// reference the configured instance name.
    #[modify_schema(field = issuance_protocol)]
    pub protocol: String,
    /// Attribute from the credential schema, together with the
    /// corresponding claim being made.
    #[into(with_fn = convert_inner)]
    pub claim_values: Vec<CredentialRequestClaimRestDTO>,
    /// When a credential is accepted, the holder will be redirected to the
    /// resource specified here, if redirects are enabled in the system
    /// configuration. The URI must use a scheme (for example `https`, `myapp`)
    /// that is allowed by the system configuration.
    pub redirect_uri: Option<String>,
    /// Optional profile to associate with this credential
    pub profile: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialRequestClaimDTO)]
pub(crate) struct CredentialRequestClaimRestDTO {
    /// ID of the attribute from the credential schema.
    #[into(rename = "claim_schema_id")]
    pub claim_id: Uuid,
    /// Claim being asserted in issuance.
    #[serde(default)]
    pub value: String,
    /// Path to the particular claim key within the structure of the credential schema.
    pub path: String,
}

/// Array of credentials to be checked for revocation status.
#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialRevocationCheckRequestRestDTO {
    pub credential_ids: Vec<CredentialId>,
    pub force_refresh: Option<bool>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SuspendCredentialRequestDTO)]
pub(crate) struct SuspendCredentialRequestRestDTO {
    /// Specify the time when the credential will reactivate, or omit for an indefinite suspension.
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialRevocationCheckResponseDTO)]
pub(crate) struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: Uuid,
    pub status: CredentialStateRestEnum,
    /// Indicates whether the system performed the check as planned.
    /// When using `forceRefresh`, indicates whether the external resource
    /// was reached and gave a response. For mdocs this value will only be
    /// `true` if a new MSO was issued.
    pub success: bool,
    /// Explanation of why the revocation check failed. Only present
    /// when `success: false`.
    pub reason: Option<String>,
}
