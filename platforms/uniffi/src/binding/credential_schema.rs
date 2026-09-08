use std::collections::HashMap;

use one_core::model::credential_schema::{
    CredentialSchemaExactColumn, KeyStorageSecurity, SortableCredentialSchemaColumn,
    TransactionCodeType,
};
use one_core::service::credential_schema::dto::{
    CreateCredentialSchemaV2RequestDTO, CredentialClaimSchemaMappingDTO,
    CredentialClaimSchemaRequestDTO, CredentialClaimSchemaTranslationsDTO,
    CredentialClaimSchemaV2DTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaBackgroundPropertiesResponseDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaDetailV2ResponseDTO,
    CredentialSchemaFormatRequestDTO, CredentialSchemaFormatResponseDTO,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLayoutPropertiesResponseDTO,
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaListItemV2ResponseDTO,
    CredentialSchemaLogoPropertiesRequestDTO, CredentialSchemaLogoPropertiesResponseDTO,
    CredentialSchemaShareResponseDTO, CredentialSchemaTransactionCodeDTO,
    CredentialSchemaTransactionCodeRequestDTO, CredentialSchemaTranslationsDTO,
    GetCredentialSchemaListV2ResponseDTO, ImportCredentialSchemaLayoutPropertiesDTO,
    ImportCredentialSchemaTransactionCodeDTO, ImportCredentialSchemaV2FormatDTO,
    ImportCredentialSchemaV2RequestDTO, ImportCredentialSchemaV2RequestSchemaDTO,
};
use one_dto_mapper::{
    From, Into, TryInto, convert_inner, convert_inner_of_inner, try_convert_inner,
};
use shared_types::CredentialSchemaId;

use super::OneCore;
use super::common::SortDirection;
use super::mapper::{from_i18n_string, from_i18n_string_opt, to_i18n_string, to_i18n_string_opt};
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{TimestampFormat, into_id, into_timestamp};

fn duration_from_seconds(value: Option<i64>) -> Option<time::Duration> {
    value.map(time::Duration::seconds)
}

fn seconds_from_duration(value: Option<time::Duration>) -> Option<i64> {
    value.map(time::Duration::whole_seconds)
}

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Returns detailed information about a credential schema.
    /// A credential schema defines the structure and format of a credential,
    /// including the attributes that issuers make claims about. Schemas also
    /// specify how issued credentials should be presented in wallets, whether
    /// a revocation method is used to manage credential status, and issuer
    /// preferences for suitable key storage types for wallets to use.
    #[uniffi::method]
    pub async fn get_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<CredentialSchemaDetailV2BindingDTO, BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .get_credential_schema_v2(&credential_schema_id, None)
            .await?
            .into())
    }

    /// Returns a filterable list of credential schemas.
    #[uniffi::method]
    pub async fn list_credential_schemas(
        &self,
        query: CredentialSchemaListQueryBindingDTO,
    ) -> Result<CredentialSchemaListV2BindingDTO, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .get_credential_schema_list_v2(query.try_into()?)
            .await?
            .into())
    }

    /// Produces a URL for sharing a credential schema with another mobile
    /// verifier device using the one-core.
    #[uniffi::method]
    pub async fn share_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<CredentialSchemaShareResponseBindingDTO, BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;
        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .share_credential_schema(&credential_schema_id)
            .await?
            .into())
    }

    /// Imports a credential schema shared from another mobile verifier device
    /// using the one-core.
    #[uniffi::method]
    pub async fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaV2RequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .import_credential_schema_v2(request)
            .await?
            .to_string())
    }

    /// Permanently removes a credential schema.
    #[uniffi::method]
    pub async fn delete_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<(), BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .delete_credential_schema(&credential_schema_id)
            .await?)
    }

    /// Creates a credential schema
    #[uniffi::method]
    pub async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaV2RequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request: CreateCredentialSchemaV2RequestDTO = request.try_into()?;
        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .create_credential_schema_v2(request)
            .await
            .map(|id| id.to_string())?)
    }
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(CredentialSchemaTransactionCodeDTO)]
#[uniffi(name = "CredentialSchemaTransactionCode")]
pub struct CredentialSchemaTransactionCodeBindingDTO {
    pub r#type: TransactionCodeTypeBindingEnum,
    pub length: u32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CredentialSchemaListQuery")]
pub struct CredentialSchemaListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,
    pub organisation_id: String,
    pub sort: Option<SortableCredentialSchemaColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,
    pub name: Option<String>,
    pub ids: Option<Vec<String>>,
    pub exact: Option<Vec<CredentialSchemaListQueryExactColumnBindingEnum>>,
    pub include: Option<Vec<CredentialSchemaListIncludeEntityType>>,
    pub ecosystem_schema_ids: Option<Vec<String>>,
    pub formats: Option<Vec<String>>,
    pub ecosystems: Option<Vec<String>>,
    pub uses_batch_issuance: Option<bool>,
    pub is_multiformat_schema: Option<bool>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(CredentialSchemaExactColumn)]
#[uniffi(name = "CredentialSchemaListQueryExactColumn")]
pub enum CredentialSchemaListQueryExactColumnBindingEnum {
    Name,
    SchemaId,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaShareResponseDTO)]
#[uniffi(name = "CredentialSchemaShareResponse")]
pub struct CredentialSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialSchemaColumn)]
#[uniffi(name = "SortableCredentialSchemaColumn")]
pub enum SortableCredentialSchemaColumnBindingEnum {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, From, TryInto, uniffi::Record)]
#[from(CredentialSchemaLayoutPropertiesResponseDTO)]
#[try_into(T=CredentialSchemaLayoutPropertiesRequestDTO, Error=ErrorResponseBindingDTO)]
#[uniffi(name = "CredentialSchemaLayoutProperties")]
pub struct CredentialSchemaLayoutPropertiesBindingDTO {
    #[from(with_fn = convert_inner)]
    #[try_into(with_fn = try_convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[from(with_fn = convert_inner)]
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    #[try_into(infallible)]
    pub primary_attribute: Option<String>,
    #[try_into(infallible)]
    pub secondary_attribute: Option<String>,
    #[try_into(infallible)]
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[try_into(with_fn = convert_inner, infallible)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(Clone, Debug, From, TryInto, uniffi::Record)]
#[from(CredentialSchemaBackgroundPropertiesResponseDTO)]
#[try_into(T=CredentialSchemaBackgroundPropertiesRequestDTO,  Error=ErrorResponseBindingDTO)]
#[uniffi(name = "CredentialSchemaBackgroundProperties")]
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    #[try_into(infallible)]
    pub color: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, TryInto, uniffi::Record)]
#[from(CredentialSchemaLogoPropertiesResponseDTO)]
#[try_into(T=CredentialSchemaLogoPropertiesRequestDTO, Error=ErrorResponseBindingDTO)]
#[uniffi(name = "CredentialSchemaLogoProperties")]
pub struct CredentialSchemaLogoPropertiesBindingDTO {
    #[try_into(infallible)]
    pub font_color: Option<String>,
    #[try_into(infallible)]
    pub background_color: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaCodePropertiesDTO)]
#[into(CredentialSchemaCodePropertiesDTO)]
#[uniffi(name = "CredentialSchemaCodeProperties")]
pub struct CredentialSchemaCodePropertiesBindingDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeBindingDTO,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(CredentialSchemaCodeTypeEnum)]
#[into(CredentialSchemaCodeTypeEnum)]
#[uniffi(name = "CredentialSchemaCodeType")]
pub enum CredentialSchemaCodeTypeBindingDTO {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
#[uniffi(name = "CredentialSchemaListIncludeEntityType")]
pub enum CredentialSchemaListIncludeEntityType {
    LayoutProperties,
    Translations,
}

#[derive(Clone, Debug, uniffi::Record, TryInto)]
#[try_into(T = ImportCredentialSchemaTransactionCodeDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportCredentialSchemaTransactionCode")]
pub struct ImportCredentialSchemaTransactionCodeBindingDTO {
    #[try_into(infallible)]
    pub r#type: TransactionCodeTypeBindingEnum,
    pub length: u32,
    #[try_into(infallible)]
    pub description: Option<String>,
}

#[derive(From, Clone, Debug, Into, uniffi::Enum)]
#[from(TransactionCodeType)]
#[into(TransactionCodeType)]
#[uniffi(name = "TransactionCodeType")]
pub enum TransactionCodeTypeBindingEnum {
    Numeric,
    Alphanumeric,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=ImportCredentialSchemaLayoutPropertiesDTO, Error=ErrorResponseBindingDTO)]
#[uniffi(name = "ImportCredentialSchemaLayoutProperties")]
pub struct ImportCredentialSchemaLayoutPropertiesBindingDTO {
    #[try_into(with_fn = try_convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[try_into(with_fn = try_convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    #[try_into(infallible)]
    pub primary_attribute: Option<String>,
    #[try_into(infallible)]
    pub secondary_attribute: Option<String>,
    #[try_into(infallible)]
    pub picture_attribute: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(From, Clone, Debug, Into, uniffi::Enum)]
#[from(KeyStorageSecurity)]
#[into(KeyStorageSecurity)]
#[uniffi(name = "KeyStorageSecurity")]
pub enum KeyStorageSecurityBindingEnum {
    High,
    Moderate,
    EnhancedBasic,
    Basic,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaTranslationsDTO)]
#[into(CredentialSchemaTranslationsDTO)]
#[uniffi(name = "CredentialSchemaTranslations")]
pub struct CredentialSchemaTranslationsBindingDTO {
    #[from(with_fn = from_i18n_string)]
    #[into(with_fn = to_i18n_string)]
    pub name: HashMap<String, String>,
    #[from(with_fn = from_i18n_string_opt)]
    #[into(with_fn = to_i18n_string_opt)]
    pub description: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialClaimSchemaTranslationsDTO)]
#[into(CredentialClaimSchemaTranslationsDTO)]
#[uniffi(name = "CredentialClaimSchemaTranslations")]
pub struct CredentialClaimSchemaTranslationsBindingDTO {
    #[from(with_fn = from_i18n_string)]
    #[into(with_fn = to_i18n_string)]
    pub name: HashMap<String, String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaFormatResponseDTO)]
#[uniffi(name = "CredentialSchemaFormatResponse")]
pub struct CredentialSchemaFormatResponseBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub format: String,
    pub ecosystem_schema_id: String,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialClaimSchemaMappingDTO)]
#[into(CredentialClaimSchemaMappingDTO)]
#[uniffi(name = "CredentialClaimSchemaMapping")]
pub struct CredentialClaimSchemaMappingBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub format: String,
    pub technical_key: String,
    pub namespace: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialClaimSchemaV2DTO)]
#[uniffi(name = "ClaimSchema")]
pub struct CredentialClaimSchemaV2BindingDTO {
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
    pub claims: Vec<CredentialClaimSchemaV2BindingDTO>,
    #[from(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingBindingDTO>>,
    pub translations: CredentialClaimSchemaTranslationsBindingDTO,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaDetailV2ResponseDTO)]
#[uniffi(name = "CredentialSchemaDetail")]
pub struct CredentialSchemaDetailV2BindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub formats: Vec<CredentialSchemaFormatResponseBindingDTO>,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaV2BindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub requires_wallet_instance_attestation: bool,
    #[from(with_fn = convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeBindingDTO>,
    pub translations: CredentialSchemaTranslationsBindingDTO,
    #[from(with_fn = seconds_from_duration)]
    pub expiration: Option<i64>,
    #[from(with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaListItemV2ResponseDTO)]
#[uniffi(name = "CredentialSchemaListItem")]
pub struct CredentialSchemaListItemV2BindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn = convert_inner)]
    pub formats: Vec<CredentialSchemaFormatResponseBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub allow_revocation: Option<bool>,
    pub batch_size: Option<i32>,
    pub requires_wallet_instance_attestation: bool,
    #[from(with_fn = seconds_from_duration)]
    pub expiration: Option<i64>,
    #[from(with_fn = convert_inner)]
    pub ecosystem: Option<String>,
    #[from(with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialSchemaListV2ResponseDTO)]
#[uniffi(name = "CredentialSchemaList")]
pub struct CredentialSchemaListV2BindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialSchemaListItemV2BindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(CredentialSchemaFormatRequestDTO)]
#[uniffi(name = "CredentialSchemaFormatRequest")]
pub struct CredentialSchemaFormatRequestBindingDTO {
    pub format: String,
    pub ecosystem_schema_id: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(CredentialClaimSchemaRequestDTO)]
#[uniffi(name = "CredentialClaimSchemaRequest")]
pub struct CredentialClaimSchemaRequestBindingDTO {
    pub key: String,
    pub datatype: String,
    pub required: bool,
    pub array: Option<bool>,
    #[into(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaRequestBindingDTO>,
    #[into(with_fn = convert_inner_of_inner)]
    pub mappings: Option<Vec<CredentialClaimSchemaMappingBindingDTO>>,
    #[into(with_fn = convert_inner)]
    pub translations: Option<CredentialClaimSchemaTranslationsBindingDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CredentialSchemaTransactionCodeRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CredentialSchemaTransactionCodeRequest")]
pub struct CredentialSchemaTransactionCodeRequestBindingDTO {
    #[try_into(infallible)]
    pub r#type: TransactionCodeTypeBindingEnum,
    pub length: u32,
    #[try_into(infallible)]
    pub description: Option<String>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = CreateCredentialSchemaV2RequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "CreateCredentialSchemaRequest")]
pub struct CreateCredentialSchemaV2RequestBindingDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible, with_fn = convert_inner)]
    pub formats: Vec<CredentialSchemaFormatRequestBindingDTO>,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible, with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaRequestBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[try_into(infallible)]
    pub allow_revocation: Option<bool>,
    #[try_into(infallible)]
    pub batch_size: Option<i32>,
    #[try_into(infallible)]
    pub requires_wallet_instance_attestation: bool,
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeRequestBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsBindingDTO>,
    #[try_into(with_fn = try_convert_inner)]
    pub embedded_disclosure_policy: Option<DisclosurePolicyCreateRequestBindingDTO>,
    #[try_into(infallible, with_fn = duration_from_seconds)]
    pub expiration: Option<i64>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub ecosystem: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(ImportCredentialSchemaV2FormatDTO)]
#[uniffi(name = "ImportCredentialSchemaFormat")]
pub struct ImportCredentialSchemaV2FormatBindingDTO {
    pub format: String,
    pub ecosystem_schema_id: String,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ImportCredentialSchemaClaimSchema")]
pub struct ImportCredentialSchemaV2ClaimSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub required: bool,
    pub key: String,
    pub datatype: String,
    pub array: Option<bool>,
    pub claims: Option<Vec<ImportCredentialSchemaV2ClaimSchemaBindingDTO>>,
    pub mappings: Option<Vec<CredentialClaimSchemaMappingBindingDTO>>,
    pub translations: Option<CredentialClaimSchemaTranslationsBindingDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaV2RequestSchemaDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportCredentialSchemaRequestSchema")]
pub struct ImportCredentialSchemaV2RequestSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible, with_fn = convert_inner)]
    pub formats: Vec<ImportCredentialSchemaV2FormatBindingDTO>,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(with_fn = try_convert_inner)]
    pub claims: Vec<ImportCredentialSchemaV2ClaimSchemaBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesBindingDTO>,
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[try_into(infallible)]
    pub requires_wallet_instance_attestation: Option<bool>,
    #[try_into(with_fn = try_convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeBindingDTO>,
    #[try_into(infallible)]
    pub allow_revocation: Option<bool>,
    #[try_into(infallible)]
    pub batch_size: Option<i32>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub translations: Option<CredentialSchemaTranslationsBindingDTO>,
    #[try_into(with_fn = try_convert_inner)]
    pub embedded_disclosure_policy: Option<DisclosurePolicyBindingDTO>,
    #[try_into(infallible, with_fn = duration_from_seconds)]
    pub expiration: Option<i64>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaV2RequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportCredentialSchemaRequest")]
pub struct ImportCredentialSchemaV2RequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    pub schema: ImportCredentialSchemaV2RequestSchemaBindingDTO,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DisclosurePolicy")]
pub struct DisclosurePolicyBindingDTO {
    pub id: String,
    pub policy: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub options: Option<DisclosurePolicyOptionsBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DisclosurePolicyCreateRequest")]
pub struct DisclosurePolicyCreateRequestBindingDTO {
    pub policy: String,
    pub description: Option<String>,
    pub url: Option<String>,
    pub options: Option<DisclosurePolicyOptionsBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DisclosurePolicyOptions")]
pub struct DisclosurePolicyOptionsBindingDTO {
    pub values: Vec<DisclosurePolicyOptionBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DisclosurePolicyOption")]
pub struct DisclosurePolicyOptionBindingDTO {
    pub dn: Option<String>,
    pub entitlement: Option<String>,
    pub serial: Option<String>,
}
