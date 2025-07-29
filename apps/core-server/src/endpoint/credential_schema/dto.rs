use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaListItemResponseDTO,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use proc_macros::options_not_nullable;
use serde::{Deserialize, Serialize};
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::dto::common::ListQueryParamsRest;
use crate::serialize::{front_time, front_time_option};

/// Credential schema details.
#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaListItemResponseDTO)]
pub struct CredentialSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time_option")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    /// Indication of what type of key storage the wallet should use.
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    pub imported_source_url: String,
    /// Part of the `credentialSchema` property.
    pub schema_id: String,
    /// Part of the `credentialSchema` property.
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub external_schema: bool,
}

/// Part of the `credentialSchema` property.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, From, Into)]
#[from(one_core::service::credential::dto::CredentialSchemaType)]
#[into(one_core::service::credential::dto::CredentialSchemaType)]
pub enum CredentialSchemaType {
    ProcivisOneSchema2024,
    FallbackSchema2024,
    #[serde(rename = "mdoc")]
    Mdoc,
    SdJwtVc,
    #[serde(untagged)]
    Other(String),
}

impl From<String> for CredentialSchemaType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ProcivisOneSchema2024" => CredentialSchemaType::ProcivisOneSchema2024,
            "FallbackSchema2024" => CredentialSchemaType::FallbackSchema2024,
            "SdJwtVc" => CredentialSchemaType::SdJwtVc,
            "mdoc" => CredentialSchemaType::Mdoc,
            _ => Self::Other(value),
        }
    }
}

impl utoipa::PartialSchema for CredentialSchemaType {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        let known = utoipa::openapi::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::SchemaType::Type(
                utoipa::openapi::Type::String,
            ))
            .enum_values(Some([
                "ProcivisOneSchema2024",
                "FallbackSchema2024",
                "SdJwtVc",
                "mdoc",
            ]));

        utoipa::openapi::schema::OneOfBuilder::new()
            .item(known)
            .item(utoipa::schema!(String))
            .into()
    }
}

impl utoipa::ToSchema for CredentialSchemaType {}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[from(CredentialSchemaDetailResponseDTO)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// Part of the `credentialSchema` property.
    pub schema_id: String,
    /// Part of the `credentialSchema` property.
    pub schema_type: CredentialSchemaType,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
    pub external_schema: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialClaimSchemaDTO)]
pub struct CredentialClaimSchemaResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: bool,
    #[from(with_fn = convert_inner)]
    #[serde(default)]
    #[schema(no_recursion)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSchemasExactColumn {
    Name,
    SchemaId,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemasFilterQueryParamsRest {
    pub organisation_id: OrganisationId,
    /// Return only entities with a name starting with this string. Not case-sensitive.
    #[param(nullable = false)]
    pub name: Option<String>,
    /// Set which filters apply in an exact way.
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<CredentialSchemasExactColumn>>,
    /// Return only the credential schemas specified here by their UUID.
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialSchemaId>>,
    /// Return credential schemas associated with the specified `schemaId` or document
    /// type for ISO mdocs.
    #[param(nullable = false)]
    pub schema_id: Option<String>,
    /// Return only credential schemas which use one of the specified credential formats.
    #[param(rename = "formats[]", inline, nullable = false)]
    pub formats: Option<Vec<String>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub enum CredentialSchemaListIncludeEntityTypeRestEnum {
    LayoutProperties,
}

pub type GetCredentialSchemaQuery = ListQueryParamsRest<
    CredentialSchemasFilterQueryParamsRest,
    SortableCredentialSchemaColumnRestEnum,
    CredentialSchemaListIncludeEntityTypeRestEnum,
>;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, ToSchema, Into)]
#[serde(rename_all = "camelCase")]
#[into("one_core::model::credential_schema::SortableCredentialSchemaColumn")]
pub enum SortableCredentialSchemaColumnRestEnum {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, ToSchema, Into, From)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into("one_core::model::credential_schema::WalletStorageTypeEnum")]
#[from("one_core::model::credential_schema::WalletStorageTypeEnum")]
pub enum WalletStorageTypeRestEnum {
    Software,
    Hardware,
    RemoteSecureElement,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate, TryInto)]
#[try_into(T=CreateCredentialSchemaRequestDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    #[try_into(infallible)]
    pub name: String,
    /// Choose a credential format for credentials issued using this
    /// credential schema. Check the `format` object of the configuration
    /// for supported options and reference the configuration instance.
    #[schema(example = "SD_JWT_VC")]
    #[try_into(infallible)]
    pub format: String,
    /// Choose a revocation method for credentials issued using this
    /// credential schema. Check the `revocation` object of the configuration
    /// for supported options and reference the configuration instance.
    #[schema(example = "TOKENSTATUSLIST")]
    #[try_into(infallible)]
    pub revocation_method: String,
    /// Specify the organization.
    #[try_into(infallible)]
    pub organisation_id: Uuid,
    /// Defines the set of claims to be asserted when using this credential
    /// schema.
    #[validate(length(min = 1))]
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    /// Indication of what type of key storage the wallet should use.
    /// Note that credentials with different `walletStorageType` cannot be
    /// combined into the same proof schema.
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// Determines the general appearance of the credential in the holder's
    /// wallet and the options supported in `layoutProperties`.
    #[serde(default)]
    #[schema(default = CredentialSchemaLayoutType::default)]
    #[try_into(infallible)]
    pub layout_type: CredentialSchemaLayoutType,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    /// For credential formats requiring a schema ID, such as ISO mdoc, IETF
    /// SD-JWT VC or VC Barcodes, pass it here.
    /// For other formats, pass no value here.
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
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Into, From, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::model::credential_schema::LayoutType)]
#[from(one_core::model::credential_schema::LayoutType)]
pub enum CredentialSchemaLayoutType {
    #[default]
    Card,
    Document,
    SingleAttribute,
}

#[options_not_nullable]
#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[into(CredentialClaimSchemaRequestDTO)]
pub struct CredentialClaimSchemaRequestRestDTO {
    pub key: String,
    /// The type of data accepted for this attribute. The `DATE` datatype
    /// only accepts full date-time. See the
    /// [configuration](/configure) guide for
    /// the full reference of datatypes.
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
#[serde(rename_all = "camelCase")]
#[try_into(T=one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO, Error=ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesResponseDTO)]
pub struct CredentialSchemaLayoutPropertiesRestDTO {
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
#[serde(rename_all = "camelCase")]
#[try_into(T = one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO, Error = ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesResponseDTO)]
pub struct CredentialSchemaBackgroundPropertiesRestDTO {
    #[serde(default)]
    #[try_into(infallible)]
    pub color: Option<String>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[options_not_nullable]
#[derive(Debug, Clone, PartialEq, Eq, TryInto, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[try_into(T=one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO, Error = ServiceError)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesResponseDTO)]
pub struct CredentialSchemaLogoPropertiesRestDTO {
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
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesDTO)]
pub struct CredentialSchemaCodePropertiesRestDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeRestEnum,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodeTypeEnum)]
pub enum CredentialSchemaCodeTypeRestEnum {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Debug, Clone, From, Serialize, ToSchema)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseRestDTO {
    pub url: String,
}

#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaRequestDTO, Error = ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestRestDTO {
    #[try_into(infallible)]
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaRequestSchemaRestDTO,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, TryInto, ToSchema)]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaRequestSchemaDTO, Error=ServiceError)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestSchemaRestDTO {
    #[try_into(infallible)]
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    #[try_into(infallible)]
    pub last_modified: OffsetDateTime,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(infallible)]
    pub revocation_method: String,
    #[try_into(infallible)]
    pub organisation_id: Uuid,
    #[try_into(with_fn = convert_inner, infallible)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaType,
    #[serde(default)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[serde(default)]
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
    #[serde(default)]
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[try_into(infallible)]
    pub external_schema: bool,
}

#[options_not_nullable]
#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaClaimSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaClaimSchemaRestDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
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
#[serde(rename_all = "camelCase")]
#[try_into(T=one_core::service::credential_schema::dto::ImportCredentialSchemaLayoutPropertiesDTO, Error=ServiceError)]
pub struct ImportCredentialSchemaLayoutPropertiesRestDTO {
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
