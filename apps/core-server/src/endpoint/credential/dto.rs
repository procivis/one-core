use one_core::model::credential::{
    CredentialListIncludeEntityTypeEnum, ExactCredentialFilterColumn, SortableCredentialColumn,
};
use one_core::service::credential::dto::{
    ChangeCredentialStateDTO, CreateCredentialRequestDTO, CredentialFilterParamsDTO,
    CredentialListItemResponseDTO, CredentialRequestClaimDTO, CredentialRevocationCheckResponseDTO,
    CredentialRole, CredentialSearchTypeDTO, CredentialStateEnum, CredentialTypeEnum,
    DetailCredentialClaimResponseDTO, DetailCredentialSchemaResponseDTO,
    MdocMsoValidityResponseDTO, ShareCredentialResponseDTO, SuspendCredentialRequestDTO,
    TrustInformation, WalletInstanceAttestationDTO, WalletUnitAttestationDTO,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{From, Into, TryInto, convert_inner, convert_inner_of_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{
    CertificateId, ClaimSchemaId, CredentialFormat, CredentialId, CredentialSchemaId, DidId,
    EcosystemId, IdentifierId, InteractionId, KeyId, OrganisationId, RevocationMethodId,
};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
use crate::dto::common::trust_detail::{
    EudiTrustInformationResponseRestDTO, TrustInformationDetailResponseRestEnum,
    TrustResolutionResultRestEnum,
};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::endpoint::certificate::dto::CertificateResponseRestDTO;
use crate::endpoint::credential_schema::dto::{
    CredentialClaimSchemaResponseRestDTO, CredentialSchemaLayoutPropertiesRestDTO,
    CredentialSchemaLayoutType, CredentialSchemaListItemResponseRestDTO,
    CredentialSchemaTranslationsRestDTO, KeyStorageSecurityRestEnum,
};
use crate::endpoint::identifier::dto::GetIdentifierListItemResponseRestDTO;
use crate::serialize::{front_time, front_time_option};

#[options_not_nullable]
#[derive(Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialListItemResponseDTO)]
pub(crate) struct CredentialListItemResponseRestDTO {
    pub id: CredentialId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub consumed_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub expires_at: Option<OffsetDateTime>,
    pub state: CredentialStateRestEnum,
    pub r#type: CredentialTypeRestEnum,
    pub parent_id: Option<CredentialId>,
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
    pub webhook_destination_url: Option<String>,
    /// URI holder is redirected to after credential issuance.
    pub redirect_uri: Option<String>,
    pub ecosystem: Option<EcosystemId>,
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
pub(crate) struct GetCredentialResponseRestDTO<TClaim> {
    pub id: CredentialId,

    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub issuance_date: Option<OffsetDateTime>,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub revocation_date: Option<OffsetDateTime>,

    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub expires_at: Option<OffsetDateTime>,
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
    pub claims: Vec<TClaim>,

    /// URI holder is redirected to after credential issuance.
    pub redirect_uri: Option<String>,

    /// The role the system has in relation to the credential. For example,
    /// if the system issued the credential this value will be `ISSUER`. If
    /// the system received the credential as a wallet this value will be
    /// `HOLDER`.
    pub role: CredentialRoleRestEnum,
    pub interaction_id: Option<InteractionId>,

    /// When this credential was used in a presentation. Only used for
    /// batch item credentials.
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub consumed_at: Option<OffsetDateTime>,

    /// Differentiates between single credentials issued alone, credentials
    /// issued as part of a batch, and parent credentials which represent
    /// a batch of credentials.
    pub r#type: CredentialTypeRestEnum,

    /// Number of non-consumed batch items (if batch parent).
    pub remaining_batch_item_count: Option<u32>,

    /// Batch parent (if batch item).
    pub parent_id: Option<CredentialId>,

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
    pub webhook_destination_url: Option<String>,
    /// Trust information of the issuer, if any received.
    pub trust_information: Option<TrustInformationRestDTO>,
    /// Optional subscriber information associated with this credential.
    pub subscriber_information: Option<String>,
    pub ecosystem: Option<EcosystemId>,
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

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialTrustInformationDetailResponseRestDTO {
    /// EUDI trust information received from Access Certificates,
    /// Registration Certificates, or National Registry public APIs.
    /// Deprecated: Use `ecosystem` and `issuer` fields
    #[deprecated]
    pub eudi_ecosystem: Option<EudiTrustInformationResponseRestDTO>,

    pub ecosystem: Option<EcosystemId>,
    pub issuer: Option<TrustInformationDetailResponseRestEnum>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(TrustInformation)]
#[serde(rename_all = "camelCase")]
pub struct TrustInformationRestDTO {
    #[serde(serialize_with = "front_time")]
    received_at: OffsetDateTime,
    name: Option<String>,
    result: TrustResolutionResultRestEnum,
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
    pub id: CredentialSchemaId,
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
    /// Storage security requirements the wallet's key storage must meet.
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
    pub translations: CredentialSchemaTranslationsRestDTO,
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
    Expired,
    Expiring,
}

/// The type representation of the credential in the system.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, From, Into)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[from(CredentialTypeEnum)]
#[into(CredentialTypeEnum)]
pub(crate) enum CredentialTypeRestEnum {
    Single,
    BatchParent,
    BatchItem,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[into(CredentialSearchTypeDTO)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SearchType {
    ClaimName,
    ClaimValue,
    CredentialSchemaName,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = CredentialFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetCredentialQuery
pub(crate) struct CredentialsFilterQueryParamsRest {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only credentials with a name starting with this string.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Filter by one or more country profiles.
    #[param(rename = "profiles[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub profiles: Option<Vec<String>>,
    /// Filter credentials by one or more roles: issued by the system,
    /// verified by the system, or held by the system as a wallet.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "roles[]", inline, nullable = false)]
    pub roles: Option<Vec<CredentialRoleRestEnum>>,
    /// Set which filters apply in an exact way.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<ExactCredentialFilterColumnRestEnum>>,
    /// Filter by one or more UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ids: Option<Vec<CredentialId>>,
    /// Return only batch credentials under this batch parent.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub parent_id: Option<CredentialId>,
    /// Filter by one or more credential states.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "states[]", inline, nullable = false)]
    pub states: Option<Vec<CredentialStateRestEnum>>,
    /// Filter credentials by one or more types: part of a batch or standalone credential
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "types[]", inline, nullable = false)]
    pub types: Option<Vec<CredentialTypeRestEnum>>,
    /// Filter by one or more identifier IDs.
    #[param(rename = "issuers[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub issuers: Option<Vec<IdentifierId>>,
    /// Search for a string.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub search_text: Option<String>,
    /// Changes where `searchText` is searched. To search credentials,
    /// choose one or more `searchType`s and pass a `searchText`.
    #[try_into(infallible, with_fn = convert_inner_of_inner)]
    #[param(rename = "searchType[]", inline, nullable = false)]
    pub search_type: Option<Vec<SearchType>>,

    #[param(rename = "credentialSchemaIds[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub credential_schema_ids: Option<Vec<CredentialSchemaId>>,

    /// Return only credentials conforming to one of the specified ecosystems.
    #[param(rename = "ecosystems[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ecosystems: Option<Vec<EcosystemId>>,

    /// Return only credentials created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credentials created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credentials last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credentials last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,
    /// Return only credentials issued after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub issuance_date_after: Option<OffsetDateTime>,
    /// Return only credentials issued before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub issuance_date_before: Option<OffsetDateTime>,
    /// Return only credentials revoked after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub revocation_date_after: Option<OffsetDateTime>,
    /// Return only credentials revoked before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub revocation_date_before: Option<OffsetDateTime>,
    /// Return only credentials with an expiration after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub expires_at_after: Option<OffsetDateTime>,
    /// Return only credentials with an expiration before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub expires_at_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ExactCredentialFilterColumn)]
pub(crate) enum ExactCredentialFilterColumnRestEnum {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialListIncludeEntityTypeEnum)]
pub(crate) enum CredentialListIncludeEntityTypeRestEnum {
    LayoutProperties,
    Translations,
}

pub(crate) type GetCredentialQuery = ListQueryParamsRest<
    CredentialsFilterQueryParamsRest,
    SortableCredentialColumnRestEnum,
    CredentialListIncludeEntityTypeRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(SortableCredentialColumn)]
pub(crate) enum SortableCredentialColumnRestEnum {
    CreatedDate,
    #[serde(rename = "schema.name")]
    SchemaName,
    Issuer,
    State,
    ExpiresAt,
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
    #[schema(deprecated = true, nullable = false, value_type = Option<Uuid>)]
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
    /// Set a webhook URL or MQTT topic to receive notifications of
    /// credential state changes. See
    /// [Webhooks](https://docs.procivis.ch/webhooks) for configuration.
    pub webhook_destination_url: Option<String>,
    /// Optional subscriber information associated with this credential.
    pub subscriber_information: Option<String>,
    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    #[into(with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CredentialRequestClaimDTO)]
pub(crate) struct CredentialRequestClaimRestDTO {
    /// ID of the attribute from the credential schema.
    #[into(rename = "claim_schema_id")]
    pub claim_id: ClaimSchemaId,
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

#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
#[into(ChangeCredentialStateDTO)]
pub enum PatchCredentialStateRequestRestDTO {
    Accepted,
    Revoked,
    #[serde(rename_all = "camelCase")]
    Suspended {
        #[serde(default, deserialize_with = "deserialize_timestamp")]
        #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
        suspend_end_date: Option<OffsetDateTime>,
    },
    Expiring,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialRevocationCheckResponseDTO)]
pub(crate) struct CredentialRevocationCheckResponseRestDTO {
    pub credential_id: CredentialId,
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
