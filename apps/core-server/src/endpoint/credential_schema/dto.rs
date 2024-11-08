use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaRequestDTO, CredentialClaimSchemaDTO, CredentialClaimSchemaRequestDTO,
    CredentialSchemaDetailResponseDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaListItemResponseDTO,
};
use one_dto_mapper::{convert_inner, From, Into};
use serde::{Deserialize, Serialize};
use shared_types::{CredentialSchemaId, OrganisationId};
use time::OffsetDateTime;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use validator::Validate;

use crate::dto::common::ListQueryParamsRest;
use crate::serialize::{front_time, front_time_option};

/// Credential schema details.
/// See the [credential schemas](/api/resources/credential_schemas) guide.
#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, From)]
#[serde(rename_all = "camelCase")]
#[from(CredentialSchemaListItemResponseDTO)]
pub struct CredentialSchemaListItemResponseRestDTO {
    pub id: Uuid,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(
        serialize_with = "front_time_option",
        skip_serializing_if = "Option::is_none"
    )]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub deleted_at: Option<OffsetDateTime>,
    #[serde(serialize_with = "front_time")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    /// Indication of what type of key storage the wallet should
    /// use. See the [wallet storage type](/api/resources/credential_schemas#wallet-storage-type) guide.
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    pub imported_source_url: String,
    /// See the [credentialSchema property](/api/resources/credential_schemas#credentialschema-property) guide.
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
}

/// See the [credentialSchema property](/api/resources/credential_schemas#credentialschema-property) guide.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize, From, Into)]
#[from(one_core::service::credential::dto::CredentialSchemaType)]
#[into(one_core::service::credential::dto::CredentialSchemaType)]
pub enum CredentialSchemaType {
    ProcivisOneSchema2024,
    FallbackSchema2024,
    #[serde(rename = "mdoc")]
    Mdoc,
    #[serde(untagged)]
    Other(String),
}

impl From<String> for CredentialSchemaType {
    fn from(value: String) -> Self {
        match value.as_str() {
            "ProcivisOneSchema2024" => CredentialSchemaType::ProcivisOneSchema2024,
            "FallbackSchema2024" => CredentialSchemaType::FallbackSchema2024,
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
                "mdoc",
            ]));

        utoipa::openapi::schema::OneOfBuilder::new()
            .item(known)
            .item(utoipa::schema!(String))
            .into()
    }
}

impl utoipa::ToSchema for CredentialSchemaType {}

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
    /// See the [credentialSchema property](/api/resources/credential_schemas#credentialschema-property) guide.
    pub schema_id: String,
    pub schema_type: CredentialSchemaType,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: bool,
}

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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(no_recursion)]
    pub claims: Vec<CredentialClaimSchemaResponseRestDTO>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, ToSchema)]
#[serde(rename_all = "camelCase")]
pub enum CredentialSchemasExactColumn {
    Name,
    SchemaId,
    Format,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, IntoParams)]
#[serde(rename_all = "camelCase")]
pub struct CredentialSchemasFilterQueryParamsRest {
    pub organisation_id: OrganisationId,
    #[param(nullable = false)]
    pub name: Option<String>,
    #[param(rename = "exact[]", inline, nullable = false)]
    pub exact: Option<Vec<CredentialSchemasExactColumn>>,
    #[param(rename = "ids[]", inline, nullable = false)]
    pub ids: Option<Vec<CredentialSchemaId>>,
    #[param(nullable = false)]
    pub schema_id: Option<String>,
    #[param(nullable = false)]
    pub format: Option<String>,
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
#[serde(rename_all = "UPPERCASE")]
#[into("one_core::model::credential_schema::WalletStorageTypeEnum")]
#[from("one_core::model::credential_schema::WalletStorageTypeEnum")]
pub enum WalletStorageTypeRestEnum {
    Software,
    Hardware,
}

#[derive(Clone, Debug, Deserialize, Serialize, ToSchema, Validate, Into)]
#[into(CreateCredentialSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct CreateCredentialSchemaRequestRestDTO {
    #[validate(length(min = 1))]
    pub name: String,
    /// Choose a credential format for credentials issued using this
    /// credential schema. See the [credential
    /// formats](/api/resources/credential_schemas#credential-formats)
    /// guide.
    pub format: String,
    /// Choose a revocation method for credentials issued using this
    /// credential schema. See the [revocation
    /// methods](/api/resources/credential_schemas#revocation-methods)
    /// guide.
    pub revocation_method: String,
    /// Specify the organization.
    pub organisation_id: Uuid,
    /// Defines the set of claims to be asserted when using this credential
    /// schema. See the [claims
    /// object](/api/resources/credential_schemas#claims-object) guide.
    #[into(with_fn = convert_inner)]
    #[validate(length(min = 1))]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
    /// Indication of what type of key storage the wallet should use. See
    /// the [wallet storage
    /// type](/api/resources/credential_schemas#wallet-storage-type) guide.
    /// Note that credentials with different `walletStorageType` cannot be
    /// combined into the same proof schema.
    #[into(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    /// Determines the general appearance of the credential in the holder's
    /// wallet and the options supported in `layoutProperties`. See the
    /// [credentials
    /// designer](/api/resources/credential_schemas#credentials-designer)
    /// guide.
    #[serde(default)]
    #[schema(default = CredentialSchemaLayoutType::default)]
    pub layout_type: CredentialSchemaLayoutType,
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRestDTO>,
    /// For `mdoc` credentials, specify the `DocType` here. For physical
    /// credential verification, specify the `schemaId` here. For all other
    /// credential formats do not pass a value here. See the [mdoc
    /// implementation](/guides/mdocs) and [physical
    /// credentials](/guides/physical_credentials) guides.
    pub schema_id: Option<String>,
    /// If `true` and the chosen revocation method allows for suspension,
    /// credentials issued with this schema can be suspended.
    pub allow_suspension: Option<bool>,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize, ToSchema, Into)]
#[into(CredentialClaimSchemaRequestDTO)]
pub struct CredentialClaimSchemaRequestRestDTO {
    pub key: String,
    /// The type of data accepted for this attribute. See the
    /// [datatypes](/api/datatypes) guide.
    pub datatype: String,
    pub required: bool,
    /// If `true`, an array can be passed for this attribute during issuance.
    pub array: Option<bool>,
    /// If the `datatype` is `OBJECT`, the nested claims go in this array.
    /// Otherwise this array is empty. See the [claims object](/api/resources/credential_schemas#claims-object) guide.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[into(with_fn = convert_inner)]
    #[schema(no_recursion)]
    pub claims: Vec<CredentialClaimSchemaRequestRestDTO>,
}

/// Design the appearance of the credential in the holder's wallet. See the [credentials designer](/api/resources/credential_schemas#credentials-designer) guide.
#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct CredentialSchemaLayoutPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secondary_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_attribute: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesRestDTO {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub font_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub background_color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Into, From, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO)]
#[from(one_core::service::credential_schema::dto::CredentialSchemaCodePropertiesRequestDTO)]
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

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaRequestDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestRestDTO {
    pub organisation_id: OrganisationId,
    pub schema: ImportCredentialSchemaRequestSchemaRestDTO,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaRequestSchemaDTO)]
#[serde(rename_all = "camelCase")]
pub struct ImportCredentialSchemaRequestSchemaRestDTO {
    pub id: Uuid,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    #[schema(value_type = String, example = "2023-06-09T14:19:57.000Z")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: Uuid,
    #[into(with_fn = convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
    #[into(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeRestEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub schema_type: CredentialSchemaType,
    #[into(with_fn = convert_inner)]
    pub layout_type: Option<CredentialSchemaLayoutType>,
    #[into(with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesRestDTO>,
    pub allow_suspension: Option<bool>,
}

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
    pub array: Option<bool>,
    #[into(with_fn = convert_inner)]
    #[serde(default)]
    #[schema(no_recursion)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaRestDTO>,
}

#[derive(Clone, Debug, Deserialize, Into, ToSchema)]
#[serde(rename_all = "camelCase")]
#[into(one_core::service::credential_schema::dto::ImportCredentialSchemaLayoutPropertiesDTO)]
pub struct ImportCredentialSchemaLayoutPropertiesRestDTO {
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesRestDTO>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesRestDTO>,
    #[serde(default)]
    pub primary_attribute: Option<String>,
    #[serde(default)]
    pub secondary_attribute: Option<String>,
    #[serde(default)]
    pub picture_attribute: Option<String>,
    #[serde(default)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesRestDTO>,
}
