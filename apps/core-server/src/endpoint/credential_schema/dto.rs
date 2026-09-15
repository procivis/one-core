use one_core::model::credential_schema::{CredentialSchemaExactColumn, TransactionCodeType};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CreateCredentialSchemaV2RequestDTO, CredentialClaimSchemaDTO,
    CredentialClaimSchemaMappingDTO, CredentialClaimSchemaRequestDTO,
    CredentialClaimSchemaTranslationsDTO, CredentialClaimSchemaV2DTO,
    CredentialSchemaDcqlResponseDTO, CredentialSchemaDetailResponseDTO,
    CredentialSchemaDetailV2ResponseDTO, CredentialSchemaFilterParamsDTO,
    CredentialSchemaFormatRequestDTO, CredentialSchemaFormatResponseDTO,
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaListItemResponseDTO,
    CredentialSchemaListItemV2ResponseDTO, CredentialSchemaTransactionCodeDTO,
    CredentialSchemaTransactionCodeRequestDTO, CredentialSchemaTranslationsDTO,
    CredentialSchemaV2FilterParamsDTO, CredentialSchemaWalletAttestationDTO,
    DisclosurePolicyCreateRequest, ImportCredentialSchemaV2FormatDTO,
    ImportCredentialSchemaV2RequestDTO, ImportCredentialSchemaV2RequestSchemaDTO,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use serde_with::{DurationSeconds, serde_as};
use shared_types::i18n::I18nString;
use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialSchemaId, EcosystemId, OrganisationId,
    RevocationMethodId,
};
use standardized_types::etsi_119_472::disclosure_policy::DisclosurePolicy;
use standardized_types::openid4vp::dcql;
use time::{Duration, OffsetDateTime};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::deserialize::{deserialize_duration_seconds, deserialize_timestamp};
use crate::dto::common::{Boolean, ListQueryParamsRest};
use crate::dto::mapper::fallback_organisation_id_from_session;
use crate::serialize::{front_time, front_time_option};

/// Credential schema details.
#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaListItemResponseDTO)]
pub(crate) struct CredentialSchemaListItemResponseRestDTO {
    /// UUID of this credential schema. Use this value as `credentialSchemaId`
    /// when creating credentials with this schema.
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    pub imported_source_url: String,
    /// Document type or credential type identifier used by the credential
    /// format. This is the semantic identifier for the credential type, not
    /// the database ID of this schema record.
    pub schema_id: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    #[from(with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsRestDTO>,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaListItemV2ResponseDTO)]
pub(crate) struct CredentialSchemaListItemV2ResponseRestDTO {
    /// UUID of this credential schema. Use this value as `credentialSchemaId`
    /// when creating credentials with this schema.
    pub id: CredentialSchemaId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(nullable = false, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub formats: Vec<CredentialSchemaFormatResponseRestDTO>,
    pub wallet_attestation: CredentialSchemaWalletAttestationRestDTO,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    #[from(with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsRestDTO>,
    /// Administrative lifetime, in seconds, applied to credentials issued
    /// from this schema.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>)]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialSchemaDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaResponseRestDTO {
    /// UUID of this credential schema. Use this value as `credentialSchemaId`
    /// when creating credentials with this schema.
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    pub organisation_id: OrganisationId,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    /// Document type or credential type identifier used by the credential
    /// format. This is the semantic identifier for the credential type, not
    /// the database ID of this schema record.
    pub schema_id: String,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub requires_wallet_instance_attestation: bool,
    #[from(with_fn = convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeRestDTO>,
    #[from(with_fn = convert_inner)]
    pub dcql: Option<CredentialSchemaDcqlResponseRestDTO>,
    pub translations: CredentialSchemaTranslationsRestDTO,
    /// Administrative lifetime, in seconds, applied to credentials issued
    /// from this schema.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>)]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaDcqlResponseDTO)]
pub struct CredentialSchemaDcqlResponseRestDTO {
    #[serde(flatten)]
    pub format: dcql::CredentialFormat,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialSchemaTransactionCodeDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaTransactionCodeRestDTO {
    pub r#type: TransactionCodeTypeRestEnum,
    pub length: u32,
    pub description: Option<String>,
}

/// Wallet attestation requirements the holder's wallet must meet for
/// credential issuance.
#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From, Into)]
#[from(CredentialSchemaWalletAttestationDTO)]
#[into(CredentialSchemaWalletAttestationDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaWalletAttestationRestDTO {
    /// If `true`, the wallet must present a wallet instance attestation
    /// during issuance.
    #[serde(default)]
    pub require_instance_attestation: bool,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub key_storage_security_level: Option<KeyStorageSecurityRestEnum>,
    /// Preferred status maintenance lifetime, in seconds, of the key
    /// attestation the credential is bound to. Must be greater than 0 if
    /// specified.
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>, minimum = 1)]
    pub preferred_key_storage_attestation_lifetime: Option<Duration>,
    /// Preferred status maintenance lifetime, in seconds, of the wallet
    /// instance attestation. Must be greater than 0 if specified.
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>, minimum = 1)]
    pub preferred_instance_attestation_lifetime: Option<Duration>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialClaimSchemaDTO)]
pub(crate) struct CredentialClaimSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[from(with_fn = convert_inner)]
    #[schema(no_recursion)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
    pub translations: CredentialClaimSchemaTranslationsRestDTO,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaExactColumn)]
pub(crate) enum CredentialSchemasExactColumn {
    Name,
    SchemaId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaExactColumn)]
pub(crate) enum CredentialSchemasV2ExactColumn {
    Name,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = CredentialSchemaFilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetCredentialSchemaQuery
pub(crate) struct CredentialSchemasFilterQueryParamsRest {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only entities with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Set which filters apply in an exact way.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<CredentialSchemasExactColumn>>,
    /// Filter by specific UUIDs.
    #[try_into(rename = "credential_schema_ids", infallible)]
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialSchemaId>>,
    /// Return credential schemas associated with the specified `ecosystemSchemaId`.
    /// This is the DocType for ISO mdocs and the `vct` for SD-JWT VCs.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub schema_id: Option<String>,
    /// Return only credential schemas which use one of the specified credential formats.
    #[param(rename = "formats[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub formats: Option<Vec<CredentialFormat>>,

    #[param(rename = "ecosystems[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ecosystems: Option<Vec<EcosystemId>>,

    /// Return only credential schemas with matching wallet instance attestation requirement.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(inline, nullable = false)]
    pub requires_wallet_instance_attestation: Option<Boolean>,

    /// Return only credential schemas with a matching key storage security requirement.
    #[try_into(rename = "key_storage_security", with_fn = convert_inner_of_inner, infallible)]
    #[param(rename = "keySecurityLevels[]", inline, nullable = false)]
    pub key_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,

    /// Return only credential schemas created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credential schemas created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credential schemas last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credential schemas last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,

    /// Return only credential schemas which support batch issuance.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(nullable = false)]
    pub uses_batch_issuance: Option<Boolean>,

    /// Return only credential schemas with multiple formats.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(nullable = false)]
    pub is_multiformat_schema: Option<Boolean>,

    /// Return credential schemas associated with any of the specified schema IDs.
    /// Works across all format entries of a credential schema.
    #[try_into(infallible)]
    #[param(rename = "schemaIds[]", inline, nullable = false)]
    pub schema_ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub(crate) enum CredentialSchemaListIncludeEntityTypeRestEnum {
    LayoutProperties,
    Translations,
}

pub(crate) type GetCredentialSchemaQuery = ListQueryParamsRest<
    CredentialSchemasFilterQueryParamsRest,
    SortableCredentialSchemaColumnRestEnum,
    CredentialSchemaListIncludeEntityTypeRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential_schema::SortableCredentialSchemaColumn")]
pub(crate) enum SortableCredentialSchemaColumnRestEnum {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into("one_core::model::credential_schema::KeyStorageSecurity")]
#[from("one_core::model::credential_schema::KeyStorageSecurity")]
pub(crate) enum KeyStorageSecurityRestEnum {
    High,
    Moderate,
    EnhancedBasic,
    Basic,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryInto, ModifySchema)]
#[try_into(T=CreateCredentialSchemaRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateCredentialSchemaRequestRestDTO {
    /// Provide a name for this schema.
    #[schema(min_length = 1)]
    #[try_into(infallible)]
    pub name: String,
    /// Choose a credential format for credentials issued using this
    /// credential schema. Check the `format` object of the configuration
    /// for supported options and reference the configuration instance.
    #[modify_schema(field = format)]
    #[try_into(infallible)]
    pub format: String,
    /// Choose a revocation method for credentials issued using this
    /// credential schema. Check the `revocation` object of the configuration
    /// for supported options and reference the configuration instance.
    #[modify_schema(field = revocation)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub revocation_method: Option<String>,
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Defines the set of claims to be asserted when using this credential
    /// schema.
    #[schema(min_items = 1)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    /// Specifies key storage security requirements that the holder's wallet
    /// must meet for credential issuance.
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    /// kept for backwards compatibility
    #[serde(default, skip_serializing)]
    #[schema(ignore)]
    #[try_into(skip)]
    #[deprecated]
    #[expect(unused)]
    pub layout_type: CredentialSchemaLayoutType,
    /// Credential appearance design.
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    /// Identifier for the credential schema. For ISO mdoc, this specifies
    /// the DocType (for example, `org.iso.18013.5.1.mDL`). For SD-JWT VC,
    /// this specifies the `vct` value. If omitted, the system auto-generates
    /// an identifier using the credential schema's UUID. Must be unique
    /// within the organization.
    #[schema(example = "org.iso.18013.5.1.mDL")]
    #[serde(default)]
    #[try_into(infallible)]
    pub schema_id: Option<String>,
    /// If `true` and the chosen revocation method allows for suspension,
    /// credentials issued with this schema can be suspended.
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[serde(default)]
    #[try_into(skip)]
    #[deprecated]
    pub external_schema: Option<bool>,
    #[serde(default)]
    #[try_into(infallible)]
    pub requires_wallet_instance_attestation: bool,
    /// Optional transaction code configuration. When included, credentials
    /// issued from this schema will require holders to submit a generated
    /// one-time code to complete issuance.
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestRestDTO>,
    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into)]
#[into(CredentialClaimSchemaMappingDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialClaimSchemaMappingRestDTO {
    pub format: String,
    pub technical_key: String,
    pub namespace: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryInto)]
#[try_into(T=CredentialSchemaTransactionCodeRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialSchemaTransactionCodeRequestRestDTO {
    /// Character set for generated codes. `NUMERIC` uses digits 0-9.
    /// `ALPHANUMERIC` uses letters and digits.
    #[try_into(infallible)]
    pub r#type: TransactionCodeTypeRestEnum,
    /// Number of characters in generated codes. Must be between 4 and 10.
    pub length: u32,
    /// Optional context provided to holders about the transaction code,
    /// such as where to find it or how to use it. Maximum 300 characters.
    #[try_into(infallible)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(TransactionCodeType)]
#[from(TransactionCodeType)]
pub enum TransactionCodeTypeRestEnum {
    Numeric,
    Alphanumeric,
}

/// Deprecated, kept for backward compatibility
#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum CredentialSchemaLayoutType {
    #[default]
    Card,
    Document,
    SingleAttribute,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into, ModifySchema)]
#[serde(deny_unknown_fields)]
#[into(CredentialClaimSchemaRequestDTO)]
pub(crate) struct CredentialClaimSchemaRequestRestDTO {
    pub key: String,
    /// The type of data accepted for this attribute.
    #[modify_schema(field = datatype)]
    pub datatype: String,
    /// If `true`, a value must be provided for this claim to complete
    /// issuance.
    pub required: bool,
    /// If `true`, an array can be passed for this attribute during issuance.
    pub array: Option<bool>,
    /// If the `datatype` is `OBJECT`, the nested claims go in this array.
    /// Otherwise this array is empty.
    #[into(with_fn = convert_inner)]
    #[schema(no_recursion)]
    #[serde(default)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingRestDTO>>,
    /// Localized display strings for this claim's display name.
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub translations: Option<CredentialClaimSchemaTranslationsRestDTO>,
}

/// Design the appearance of the credential in the holder's wallet.
#[options_not_nullable]
#[derive(Debug, Clone, PartialEq, Eq, TryInto, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T=one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO, Error=ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO)]
pub(crate) struct CredentialSchemaLayoutPropertiesRestDTO {
    #[from(with_fn = convert_inner)]
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[from(with_fn = convert_inner)]
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    #[try_into(infallible)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    #[try_into(infallible)]
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}

#[options_not_nullable]
#[derive(Debug, Clone, PartialEq, Eq, TryInto, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T = one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO, Error = ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesResponseDTO)]
pub(crate) struct CredentialSchemaBackgroundPropertiesRestDTO {
    #[serde(default)]
    #[try_into(infallible)]
    pub color: Option<String>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[options_not_nullable]
#[derive(Debug, Clone, PartialEq, Eq, TryInto, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T=one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO, Error = ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesResponseDTO)]
pub(crate) struct CredentialSchemaLogoPropertiesRestDTO {
    #[serde(default)]
    #[try_into(infallible)]
    pub font_color: Option<String>,
    #[serde(default)]
    #[try_into(infallible)]
    pub background_color: Option<String>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesDTO)]
pub(crate) struct CredentialSchemaCodePropertiesRestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeRestEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
pub(crate) enum CredentialSchemaCodeTypeRestEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Debug, Clone, From, Serialize, ToSchema)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaShareResponseDTO)]
pub(crate) struct CredentialSchemaShareResponseRestDTO {
    pub url: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaRequestRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    pub schema: ImportCredentialSchemaRequestSchemaRestDTO,
}

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaRequestSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaRequestSchemaRestDTO {
    #[try_into(infallible)]
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub revocation_method: Option<String>,
    #[try_into(infallible)]
    pub organisation_id: OrganisationId,
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    /// kept for backwards compatibility
    #[serde(default)]
    #[schema(ignore)]
    #[try_into(skip)]
    #[deprecated]
    #[expect(unused)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[serde(default)]
    #[try_into(infallible)]
    pub requires_wallet_instance_attestation: Option<bool>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeRequestRestDTO>,
    #[try_into(skip)]
    #[allow(unused)]
    pub dcql: Option<CredentialSchemaDcqlResponseRestDTO>,
    #[try_into(skip)]
    #[allow(unused)]
    pub translations: Option<CredentialSchemaTranslationsRestDTO>,
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>)]
    #[try_into(infallible)]
    pub expiration: Option<Duration>,
    #[try_into(infallible)]
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, TryInto)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaTransactionCodeDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaTransactionCodeRequestRestDTO {
    #[try_into(infallible)]
    pub r#type: TransactionCodeTypeRestEnum,
    pub length: u32,
    #[try_into(infallible)]
    pub description: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaClaimSchemaRestDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    #[serde(default)]
    pub array: Option<bool>,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    #[schema(no_recursion)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingRestDTO>>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub translations: Option<CredentialClaimSchemaTranslationsRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaLayoutPropertiesDTO, Error=ServiceError)]
pub(crate) struct ImportCredentialSchemaLayoutPropertiesRestDTO {
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    #[try_into(infallible)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    #[try_into(infallible)]
    pub picture_attribute: Option<String>,
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, ModifySchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[into(CredentialSchemaFormatRequestDTO)]
pub(crate) struct CredentialSchemaFormatRequestRestDTO {
    /// Credential format identifier from the system configuration.
    #[modify_schema(field = format)]
    pub format: String,
    /// Optional schema identifier for this format (e.g. DocType for mdoc, vct for SD-JWT VC).
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub ecosystem_schema_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams, TryInto)]
#[try_into(T = CredentialSchemaV2FilterParamsDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetCredentialSchemaV2Query
pub(crate) struct CredentialSchemasV2FilterQueryParamsRest {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[param(nullable = false)]
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only entities with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub name: Option<String>,
    /// Set which filters apply in an exact way.
    #[try_into(with_fn = convert_inner_of_inner, infallible)]
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<CredentialSchemasV2ExactColumn>>,
    /// Filter by specific UUIDs.
    #[try_into(rename = "credential_schema_ids", infallible)]
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialSchemaId>>,
    /// Return only credential schemas which use one of the specified credential formats.
    #[param(rename = "formats[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub formats: Option<Vec<CredentialFormat>>,

    #[param(rename = "ecosystems[]", inline, nullable = false)]
    #[try_into(infallible)]
    pub ecosystems: Option<Vec<EcosystemId>>,

    /// Return only credential schemas with matching wallet instance attestation requirement.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(inline, nullable = false)]
    pub requires_wallet_instance_attestation: Option<Boolean>,

    /// Return only credential schemas with a matching key storage security requirement.
    #[try_into(rename = "key_storage_security", with_fn = convert_inner_of_inner, infallible)]
    #[param(rename = "keySecurityLevels[]", inline, nullable = false)]
    pub key_security_levels: Option<Vec<KeyStorageSecurityRestEnum>>,

    /// Return only credential schemas created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credential schemas created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credential schemas last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credential schemas last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    #[try_into(infallible)]
    pub last_modified_before: Option<OffsetDateTime>,

    /// Return only credential schemas which support batch issuance.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(nullable = false)]
    pub uses_batch_issuance: Option<Boolean>,

    /// Return only credential schemas with multiple formats.
    #[try_into(with_fn = convert_inner, infallible)]
    #[param(nullable = false)]
    pub is_multiformat_schema: Option<Boolean>,

    /// Return credential schemas associated with any of the specified schema IDs.
    /// Works across all format entries of a credential schema.
    #[try_into(infallible)]
    #[param(rename = "ecosystemSchemaIds[]", inline, nullable = false)]
    pub ecosystem_schema_ids: Option<Vec<String>>,

    /// Return only credential schemas with an expiration (in seconds) greater than this value.
    #[serde(default, deserialize_with = "deserialize_duration_seconds")]
    #[param(value_type = Option<i64>, nullable = false)]
    #[try_into(infallible)]
    pub expiration_greater_than: Option<Duration>,
    /// Return only credential schemas with an expiration (in seconds) less than this value.
    #[serde(default, deserialize_with = "deserialize_duration_seconds")]
    #[param(value_type = Option<i64>, nullable = false)]
    #[try_into(infallible)]
    pub expiration_less_than: Option<Duration>,
}

pub(crate) type GetCredentialSchemaV2Query = ListQueryParamsRest<
    CredentialSchemasV2FilterQueryParamsRest,
    SortableCredentialSchemaColumnRestEnum,
    CredentialSchemaListIncludeEntityTypeRestEnum,
>;

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, TryInto, ModifySchema)]
#[try_into(T = CreateCredentialSchemaV2RequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateCredentialSchemaV2RequestRestDTO {
    /// Name of the credential schema.
    #[schema(min_length = 1)]
    #[try_into(infallible)]
    pub name: String,
    /// List of credential formats supported by this schema.
    #[schema(min_items = 1)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub formats: Vec<CredentialSchemaFormatRequestRestDTO>,
    /// Required when not using STS authentication mode.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Defines the set of claims to be asserted when using this credential schema.
    #[schema(min_items = 1)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    /// Wallet attestation requirements the holder's wallet must meet for
    /// credential issuance.
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_attestation: Option<CredentialSchemaWalletAttestationRestDTO>,
    /// kept for backwards compatibility
    #[serde(default, skip_serializing)]
    #[schema(ignore)]
    #[try_into(skip)]
    #[deprecated]
    #[expect(unused)]
    pub layout_type: CredentialSchemaLayoutType,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    /// If `true` and the chosen revocation method allows for suspension,
    /// credentials issued with this schema can be suspended.
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    /// If `true`, credentials issued with this schema can be revoked.
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_revocation: Option<bool>,
    /// Minimum batch size for issuance. Must be at least 2 if specified.
    #[serde(default)]
    #[try_into(infallible)]
    pub batch_size: Option<i32>,
    /// Optional transaction code configuration.
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestRestDTO>,
    /// Localized display strings for the credential schema name and optional
    /// description.
    #[serde(default)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsRestDTO>,
    /// An optional disclosure policy embedded in the credential schema.
    /// When present, the policy is transmitted to the wallet as part of
    /// credential metadata. Wallets evaluate this policy against incoming
    /// verifier requests and warn the holder if a violation is detected. See
    /// [Embedded Disclosure Policy](https://docs.procivis.ch/issue/embedded-disclosure-policy).
    #[serde(default)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub embedded_disclosure_policy: Option<DisclosurePolicyCreateRequestRestDTO>,
    /// Administrative lifetime, in seconds, applied to credentials issued
    /// from this schema. Must be greater than 0 if specified.
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>, nullable = false, minimum = 1)]
    #[try_into(infallible)]
    pub expiration: Option<Duration>,
    #[modify_schema(field = ecosystem)]
    #[schema(nullable = false)]
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From, Into)]
#[from(DisclosurePolicyCreateRequest)]
#[into(DisclosurePolicyCreateRequest)]
pub(crate) struct DisclosurePolicyCreateRequestRestDTO {
    /// The policy type. `none` permits disclosure to any relying party.
    /// `allowList` restricts disclosure to relying parties specified in
    /// `options.values`. `rootOfTrust` permits disclosure to any relying
    /// whose certificate was issued under the CA specified in `options.values`.
    #[serde(flatten)]
    pub policy: standardized_types::etsi_119_472::disclosure_policy::PolicyType,
    /// A human-readable description of the policy, intended to help the
    /// wallet user understand why the restriction exists.
    pub description: Option<String>,
    /// A URL pointing to further information about the policy, such as
    /// your disclosure terms as an issuer.
    pub url: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialSchemaFormatResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaFormatResponseRestDTO {
    pub format: CredentialFormat,
    pub ecosystem_schema_id: String,
    #[from(with_fn = convert_inner)]
    pub dcql: Option<CredentialSchemaDcqlResponseRestDTO>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialClaimSchemaMappingDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialClaimSchemaMappingResponseRestDTO {
    pub format: CredentialFormat,
    pub technical_key: String,
    pub namespace: Option<String>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialClaimSchemaV2DTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialClaimSchemaV2ResponseRestDTO {
    pub id: ClaimSchemaId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[from(with_fn = convert_inner)]
    #[schema(no_recursion)]
    pub claims: Vec<CredentialClaimSchemaV2ResponseRestDTO>,
    #[from(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingResponseRestDTO>>,
    pub translations: CredentialClaimSchemaTranslationsRestDTO,
}

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Serialize, ToSchema, From)]
#[from(CredentialSchemaDetailV2ResponseDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaV2ResponseRestDTO {
    pub id: CredentialSchemaId,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub formats: Vec<CredentialSchemaFormatResponseRestDTO>,
    pub organisation_id: OrganisationId,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaV2ResponseRestDTO>,
    pub wallet_attestation: CredentialSchemaWalletAttestationRestDTO,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    #[from(with_fn = convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeRestDTO>,
    pub translations: CredentialSchemaTranslationsRestDTO,
    /// An optional disclosure policy embedded in the credential schema.
    /// When present, the policy is transmitted to the wallet as part of
    /// credential metadata. Wallets evaluate this policy against incoming
    /// verifier requests and warn the holder if a violation is detected. See
    /// [Embedded Disclosure Policy](https://docs.procivis.ch/issue/embedded-disclosure-policy).
    pub embedded_disclosure_policy: Option<DisclosurePolicy>,
    /// Administrative lifetime, in seconds, applied to credentials issued
    /// from this schema.
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>)]
    pub expiration: Option<Duration>,
    pub ecosystem: Option<EcosystemId>,
}

#[options_not_nullable]
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From, Into)]
#[from(CredentialSchemaTranslationsDTO)]
#[into(CredentialSchemaTranslationsDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialSchemaTranslationsRestDTO {
    pub name: I18nString,
    pub description: Option<I18nString>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, From, Into)]
#[from(CredentialClaimSchemaTranslationsDTO)]
#[into(CredentialClaimSchemaTranslationsDTO)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CredentialClaimSchemaTranslationsRestDTO {
    pub name: I18nString,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(ImportCredentialSchemaV2FormatDTO)]
pub(crate) struct ImportCredentialSchemaV2FormatRestDTO {
    /// Credential format identifier from the system configuration.
    pub format: CredentialFormat,
    /// Schema identifier for this format (e.g. DocType for mdoc, vct for SD-JWT VC).
    #[serde(alias = "schemaId")]
    pub ecosystem_schema_id: String,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=ImportCredentialSchemaV2RequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaV2RequestRestDTO {
    /// Required when not using STS authentication mode. Specifies the
    /// organizational context for this operation. When using STS
    /// authentication, this value is derived from the token.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    pub schema: ImportCredentialSchemaV2RequestSchemaRestDTO,
}

#[options_not_nullable]
#[serde_as]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=ImportCredentialSchemaV2RequestSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ImportCredentialSchemaV2RequestSchemaRestDTO {
    #[try_into(infallible)]
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    /// List of credential formats supported by this schema. At least one entry required.
    #[try_into(with_fn = convert_inner, infallible)]
    pub formats: Vec<ImportCredentialSchemaV2FormatRestDTO>,
    #[try_into(rename = "organisation_id", infallible)]
    pub organisation_id: OrganisationId,
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_attestation: Option<CredentialSchemaWalletAttestationRestDTO>,
    #[try_into(infallible)]
    pub imported_source_url: String,
    /// kept for backwards compatibility
    #[serde(default)]
    #[schema(ignore)]
    #[try_into(skip)]
    #[deprecated]
    #[expect(unused)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeRequestRestDTO>,
    /// If `true`, credentials issued with this schema can be revoked.
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_revocation: Option<bool>,
    /// Minimum batch size for issuance. Must be at least 2 if specified.
    #[serde(default)]
    #[try_into(infallible)]
    pub batch_size: Option<i32>,
    /// Translations for the credential schema name and optional description.
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub translations: Option<CredentialSchemaTranslationsRestDTO>,
    /// An optional disclosure policy embedded in the credential schema.
    /// When present, the policy is transmitted to the wallet as part of
    /// credential metadata. Wallets evaluate this policy against incoming
    /// verifier requests and warn the holder if a violation is detected. See
    /// [Embedded Disclosure Policy](https://docs.procivis.ch/issue/embedded-disclosure-policy).
    #[serde(default)]
    #[try_into(infallible)]
    pub embedded_disclosure_policy: Option<DisclosurePolicy>,
    /// Administrative lifetime, in seconds, applied to credentials issued
    /// from this schema.
    #[serde(default)]
    #[serde_as(as = "Option<DurationSeconds<i64>>")]
    #[schema(value_type = Option<i64>)]
    #[try_into(infallible)]
    pub expiration: Option<Duration>,
    #[try_into(infallible)]
    pub ecosystem: Option<EcosystemId>,
}

#[cfg(test)]
mod test {
    use similar_asserts::assert_eq;

    use super::*;

    #[test]
    fn test_shared_schema_deserializes_into_import_schema() {
        let shared = CredentialSchemaResponseRestDTO {
            id: Uuid::new_v4(),
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            name: "name".to_string(),
            format: "format".into(),
            revocation_method: Some("method".into()),
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaResponseRestDTO {
                id: Uuid::new_v4(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                key: "key".to_string(),
                datatype: "datatype".to_string(),
                required: true,
                array: true,
                claims: vec![],
                translations: CredentialClaimSchemaTranslationsRestDTO {
                    name: I18nString(std::collections::HashMap::from([(
                        "en".to_string(),
                        "key".to_string(),
                    )])),
                },
            }],
            key_storage_security: Some(KeyStorageSecurityRestEnum::Basic),
            schema_id: "schema_id".to_string(),
            imported_source_url: "imported_source_url".to_string(),
            layout_properties: Some(CredentialSchemaLayoutPropertiesRestDTO {
                background: Some(CredentialSchemaBackgroundPropertiesRestDTO {
                    color: Some("color".to_string()),
                    image: None,
                }),
                logo: Some(CredentialSchemaLogoPropertiesRestDTO {
                    font_color: Some("font_color".to_string()),
                    background_color: Some("background_color".to_string()),
                    image: None,
                }),
                primary_attribute: Some("primary_attribute".to_string()),
                secondary_attribute: Some("secondary_attribute".to_string()),
                picture_attribute: Some("picture_attribute".to_string()),
                code: Some(CredentialSchemaCodePropertiesRestDTO {
                    attribute: "attribute".to_string(),
                    r#type: CredentialSchemaCodeTypeRestEnum::Barcode,
                }),
            }),
            allow_suspension: true,
            requires_wallet_instance_attestation: true,
            transaction_code: Some(CredentialSchemaTransactionCodeRestDTO {
                r#type: TransactionCodeTypeRestEnum::Numeric,
                length: 6,
                description: Some("description".to_string()),
            }),
            dcql: None,
            translations: CredentialSchemaTranslationsRestDTO {
                name: I18nString(std::collections::HashMap::from([(
                    "en".to_string(),
                    "name".to_string(),
                )])),
                description: None,
            },
            expiration: Some(Duration::seconds(63072000)),
            ecosystem: Some("EUDI".into()),
        };

        let serialized = serde_json::to_value(shared).unwrap();

        serde_json::from_value::<ImportCredentialSchemaRequestSchemaRestDTO>(serialized).unwrap();
    }

    #[test]
    fn test_shared_schema_v2_deserializes_into_import_schema_v2() {
        let shared = CredentialSchemaV2ResponseRestDTO {
            id: Uuid::new_v4().into(),
            created_date: one_core::clock::now_utc(),
            last_modified: one_core::clock::now_utc(),
            name: "name".to_string(),
            formats: vec![CredentialSchemaFormatResponseRestDTO {
                format: "format".into(),
                ecosystem_schema_id: "schema_id".to_string(),
                dcql: None,
            }],
            organisation_id: Uuid::new_v4().into(),
            claims: vec![CredentialClaimSchemaV2ResponseRestDTO {
                id: Uuid::new_v4().into(),
                created_date: one_core::clock::now_utc(),
                last_modified: one_core::clock::now_utc(),
                key: "key".to_string(),
                datatype: "datatype".to_string(),
                required: true,
                array: true,
                claims: vec![],
                mappings: Some(vec![CredentialClaimSchemaMappingResponseRestDTO {
                    format: "format".into(),
                    technical_key: "key".to_string(),
                    namespace: None,
                }]),
                translations: CredentialClaimSchemaTranslationsRestDTO {
                    name: I18nString(std::collections::HashMap::from([(
                        "en".to_string(),
                        "key".to_string(),
                    )])),
                },
            }],
            wallet_attestation: CredentialSchemaWalletAttestationRestDTO {
                require_instance_attestation: true,
                key_storage_security_level: Some(KeyStorageSecurityRestEnum::Basic),
                preferred_key_storage_attestation_lifetime: Some(Duration::seconds(2678400)),
                preferred_instance_attestation_lifetime: Some(Duration::seconds(5356800)),
            },
            imported_source_url: "imported_source_url".to_string(),
            layout_properties: None,
            allow_suspension: true,
            allow_revocation: Some(true),
            batch_size: Some(2),
            transaction_code: Some(CredentialSchemaTransactionCodeRestDTO {
                r#type: TransactionCodeTypeRestEnum::Numeric,
                length: 6,
                description: Some("description".to_string()),
            }),
            translations: CredentialSchemaTranslationsRestDTO {
                name: I18nString(std::collections::HashMap::from([(
                    "en".to_string(),
                    "name".to_string(),
                )])),
                description: None,
            },
            embedded_disclosure_policy: None,
            expiration: Some(Duration::seconds(63072000)),
            ecosystem: Some("EUDI".into()),
        };

        let serialized = serde_json::to_value(shared).unwrap();

        let imported =
            serde_json::from_value::<ImportCredentialSchemaV2RequestSchemaRestDTO>(serialized)
                .unwrap();
        let wallet_attestation = imported.wallet_attestation.unwrap();
        assert!(wallet_attestation.require_instance_attestation);
        assert_eq!(
            wallet_attestation.key_storage_security_level,
            Some(KeyStorageSecurityRestEnum::Basic)
        );
        assert_eq!(
            wallet_attestation.preferred_key_storage_attestation_lifetime,
            Some(Duration::seconds(2678400))
        );
        assert_eq!(
            wallet_attestation.preferred_instance_attestation_lifetime,
            Some(Duration::seconds(5356800))
        );
    }
}
