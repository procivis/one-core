use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaListItemResponseDTO,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use proc_macros::{ModifySchema, options_not_nullable};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialFormat, CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::deserialize::deserialize_timestamp;
use crate::dto::common::ListQueryParamsRest;
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
    pub revocation_method: String,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    pub imported_source_url: String,
    /// Document type or credential type identifier used by the credential
    /// format. This is the semantic identifier for the credential type, not
    /// the database ID of this schema record.
    pub schema_id: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub requires_app_attestation: bool,
}

#[options_not_nullable]
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
    pub revocation_method: String,
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
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub requires_app_attestation: bool,
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
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CredentialSchemasExactColumn {
    Name,
    SchemaId,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")] // No deny_unknown_fields because of flattening inside GetCredentialSchemaQuery
pub(crate) struct CredentialSchemasFilterQueryParamsRest {
    #[param(nullable = false)]
    pub organisation_id: Option<OrganisationId>,
    /// Return only entities with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<CredentialSchemasExactColumn>>,
    /// Filter by specific UUIDs.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialSchemaId>>,
    /// Return credential schemas associated with the specified `schemaId` or document
    /// type for ISO mdocs.
    #[param(nullable = false)]
    pub schema_id: Option<String>,
    /// Return only credential schemas which use one of the specified credential formats.
    #[param(rename = "formats[]", inline, nullable = false)]
    pub formats: Option<Vec<String>>,

    /// Return only credential schemas created after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_after: Option<OffsetDateTime>,
    /// Return only credential schemas created before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub created_date_before: Option<OffsetDateTime>,
    /// Return only credential schemas last modified after this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_after: Option<OffsetDateTime>,
    /// Return only credential schemas last modified before this time.
    /// Timestamp in RFC3339 format (e.g. '2023-06-09T14:19:57.000Z').
    #[serde(default, deserialize_with = "deserialize_timestamp")]
    #[param(nullable = false)]
    pub last_modified_before: Option<OffsetDateTime>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub(crate) enum CredentialSchemaListIncludeEntityTypeRestEnum {
    LayoutProperties,
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
    Format,
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
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate, TryInto, ModifySchema)]
#[try_into(T=CreateCredentialSchemaRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CreateCredentialSchemaRequestRestDTO {
    #[validate(length(min = 1))]
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
    #[try_into(infallible)]
    pub revocation_method: String,
    /// Specify the organization.
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    /// Defines the set of claims to be asserted when using this credential
    /// schema.
    #[validate(length(min = 1))]
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    /// Specifies key storage security requirements that the holder's wallet
    /// must meet for credential issuance.
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_storage_security: Option<KeyStorageSecurityRestEnum>,
    /// Determines the general appearance of the credential in the holder's
    /// wallet and the options supported in `layoutProperties`.
    #[serde(default)]
    #[schema(default = CredentialSchemaLayoutType::default)]
    #[try_into(infallible)]
    pub layout_type: CredentialSchemaLayoutType,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    /// Document type or credential type identifier. For credential formats
    /// requiring a schema ID (check your `format` configuration for
    /// `REQUIRES_SCHEMA_ID`), specify the document type here. For ISO mdoc,
    /// use DocType. For IETF SD-JWT VC, use the vct value. For VC barcodes,
    /// use predefined types like `UtopiaEmploymentDocument`. For formats not
    /// requiring a schema ID, do not pass this field and a URI will be
    /// auto-generated.
    #[schema(example = "org.iso.18013.5.1.mDL")]
    #[serde(default)]
    #[try_into(infallible)]
    pub schema_id: Option<String>,
    /// If `true` and the chosen revocation method allows for suspension,
    /// credentials issued with this schema can be suspended.
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    /// If `true`, credentials issued using this schema will use the specified `schema_id` directly.
    /// If `false`, a Procivis credential schema will be created for the given `schema_id`.
    #[serde(default)]
    #[try_into(infallible)]
    pub external_schema: bool,
    #[serde(default)]
    #[try_into(infallible)]
    pub requires_app_attestation: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::model::credential_schema::LayoutType)]
#[from(one_core::model::credential_schema::LayoutType)]
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
    pub required: bool,
    /// If `true`, an array can be passed for this attribute during issuance.
    pub array: Option<bool>,
    /// If the `datatype` is `OBJECT`, the nested claims go in this array.
    /// Otherwise this array is empty.
    #[into(with_fn = convert_inner)]
    #[schema(no_recursion)]
    #[serde(default)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
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
    #[try_into(with_fn = fallback_organisation_id_from_session)]
    pub organisation_id: Option<OrganisationId>,
    pub schema: ImportCredentialSchemaRequestSchemaRestDTO,
}

#[options_not_nullable]
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
    #[try_into(infallible)]
    pub revocation_method: String,
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
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
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
