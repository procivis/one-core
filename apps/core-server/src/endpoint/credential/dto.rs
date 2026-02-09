use one_core::service::credential::dto::{
    CreateCredentialRequestDTO, CredentialListItemResponseDTO, CredentialRequestClaimDTO,
    CredentialRevocationCheckResponseDTO, CredentialRole, CredentialStateEnum,
    DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, ShareCredentialResponseDTO, SuspendCredentialRequestDTO,
    WalletInstanceAttestationDTO, WalletUnitAttestationDTO,
};
use one_dto_mapper::{From, Into, convert_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, CredentialFormat, CredentialId, CredentialSchemaId, DidId, IdentifierId, KeyId,
    OrganisationId, RevocationMethodId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::{ExactColumn, ListQueryParamsRest};
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::credential_schema::dto::{
    CredentialClaimSchemaResponseRestDTO, CredentialSchemaLayoutPropertiesRestDTO,
    CredentialSchemaLayoutType, CredentialSchemaListItemResponseRestDTO,
    KeyStorageSecurityRestEnum,
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

    /// Schema of the credential.
    pub schema: CredentialDetailSchemaResponseRestDTO,

    /// Issuer metadata.
    pub issuer: Option<GetIdentifierListItemResponseRestDTO>,

    /// Certificate details if issuer used an X.509 to issue credential.
    pub issuer_certificate: Option<CertificateResponseRestDTO>,

    /// Claims made by the credential issuer.
    pub claims: Vec<T>,

    /// URI holder is redirected to after credential issuance.
    pub redirect_uri: Option<String>,

    /// The role the system has in relation to the credential. For example,
    /// if the system issued the credential this value will be `ISSUER`. If
    /// the system received the credential as a wallet this value will be
    /// `HOLDER`.
    pub role: CredentialRoleRestEnum,

    /// For credentials issued with LVVC revocation.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub lvvc_issuance_date: Option<OffsetDateTime>,

    /// Scheduled date for credential reactivation.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub suspend_end_date: Option<OffsetDateTime>,
    /// Validity details for ISO mdocs.
    pub mdoc_mso_validity: Option<MdocMsoValidityResponseRestDTO>,
    /// Credential holder metadata.
    pub holder: Option<GetIdentifierListItemResponseRestDTO>,
    /// Issuance protocol used to issue this credential.
    pub protocol: String,
    /// Country profile associated with this credential.
    pub profile: Option<String>,

    /// The wallet instance attestation that was provided by the holder's wallet
    /// during credential issuance. This field is only present if the wallet
    /// provided a valid attestation when the credential was issued. The
    /// attestation serves as proof that the wallet app instance is a
    /// legitimate installation and may be required for the issuance of certain
    /// credentials.
    pub wallet_instance_attestation: Option<WalletInstanceAttestationRestDTO>,

    /// The wallet unit attestation, or "key attestation", that was provided
    /// by the holder's wallet during credential issuance. This field is
    /// only present if the wallet provided a valid attestation when the
    /// credential was issued, a requirement for the issuance of certain
    /// credentials such as EU PIDs.
    pub wallet_unit_attestation: Option<WalletUnitAttestationRestDTO>,
}

#[derive(Debug, Serialize, ToSchema, From)]
#[from(WalletInstanceAttestationDTO)]
#[serde(rename_all = "camelCase")]
pub struct WalletInstanceAttestationRestDTO {
    name: String,
    link: String,
    attestation: String,
}

#[derive(Debug, Serialize, ToSchema, From)]
#[from(WalletUnitAttestationDTO)]
#[serde(rename_all = "camelCase")]
pub struct WalletUnitAttestationRestDTO {
    attestation: String,
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

/// Credential schema used to issue the credential.
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
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    pub organisation_id: OrganisationId,
    /// Storage security requirements the key storage of the wallet must meet.
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    /// Part of the `credentialSchema` property.
    pub schema_id: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
}

#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(DetailCredentialClaimResponseDTO)]
pub(crate) struct CredentialDetailClaimResponseRestDTO {
    pub path: String,
    pub schema: CredentialClaimSchemaResponseRestDTO,
    pub value: CredentialDetailClaimValueResponseRestDTO<Self>,
}

#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(untagged)]
pub(crate) enum CredentialDetailClaimValueResponseRestDTO<T> {
    Boolean(bool),
    Float(f64),
    Integer(i64),
    String(String),
    #[schema(no_recursion)]
    Nested(Vec<T>),
}

/// The state representation of the credential in the system.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CredentialStateEnum)]
#[into(CredentialStateEnum)]
pub(crate) enum CredentialStateRestEnum {
    Created,
    Pending,
    Offered,
    Accepted,
    Suspended,
    Rejected,
    Revoked,
    Error,
    InteractionExpired,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SearchType {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetCredentialQuery
pub(crate) struct CredentialsFilterQueryParamsRest {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only credentials with a name starting with this string.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Filter by one or more country profiles.
    #[param(rename = "profiles[]", inline, nullable = false)]
    pub profiles: Option<Vec<String>>,
    /// Filter credentials by one or more roles: issued by the system,
    /// verified by the system, or held by the system as a wallet.
    #[param(rename = "roles[]", inline, nullable = false)]
    pub roles: Option<Vec<CredentialRoleRestEnum>>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactColumn>>,
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialId>>,
    /// Filter by one or more credential states.
    #[param(rename = "states[]", inline, nullable = false)]
    pub states: Option<Vec<CredentialStateRestEnum>>,
    /// Filter by one or more identifier IDs.
    #[param(rename = "issuers[]", inline, nullable = false)]
    pub issuers: Option<Vec<IdentifierId>>,
    /// Search for a string.
    #[param(nullable = false)]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. To search credentials,
    /// choose one or more `searchType`s and pass a `searchText`.
    #[param(rename = "searchType[]", inline, nullable = false)]
    pub search_type: Option<Vec<SearchType>>,

    #[param(rename = "credentialSchemaIds[]", inline, nullable = false)]
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,

    /// Return only credentials created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credentials created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credentials last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credentials last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// Return only credentials issued after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub issuance_date_after: Option<OffsetDateTime>,
    /// Return only credentials issued before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub issuance_date_before: Option<OffsetDateTime>,
    /// Return only credentials revoked after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub revocation_date_after: Option<OffsetDateTime>,
    /// Return only credentials revoked before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub revocation_date_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(one_core::model::credential::CredentialListIncludeEntityTypeEnum)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialRevocationCheckRequestRestDTO {
    pub credential_ids: Vec<CredentialId>,
    pub force_refresh: Option<bool>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(ShareCredentialResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ShareCredentialResponseRestDTO {
    /// Share URL, typically encoded as a QR code.
    pub url: String,
    /// The generated one-time code required for the holder to complete
    /// credential issuance. Must be transmitted to the holder through a
    /// secure out-of-band channel such as SMS or email to a verified
    /// contact.
    pub transaction_code: Option<String>,
    /// URL becomes unusable by wallet holder at this time. Call the share
    /// endpoint again to get a new URL.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub expires_at: Option<OffsetDateTime>,
}
