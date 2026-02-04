use one_core::model::credential_schema::{
    KeyStorageSecurity, LayoutType, SortableCredentialSchemaColumn, TransactionCodeType,
};
use one_core::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaBackgroundPropertiesResponseDTO, CredentialSchemaCodePropertiesDTO,
    CredentialSchemaCodeTypeEnum, CredentialSchemaDetailResponseDTO, CredentialSchemaFilterValue,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaLayoutPropertiesResponseDTO,
    CredentialSchemaListIncludeEntityTypeEnum, CredentialSchemaLogoPropertiesRequestDTO,
    CredentialSchemaLogoPropertiesResponseDTO, CredentialSchemaShareResponseDTO,
    CredentialSchemaTransactionCodeDTO, GetCredentialSchemaListResponseDTO,
    GetCredentialSchemaQueryDTO, ImportCredentialSchemaLayoutPropertiesDTO,
    ImportCredentialSchemaRequestDTO, ImportCredentialSchemaRequestSchemaDTO,
    ImportCredentialSchemaTransactionCodeDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use shared_types::CredentialSchemaId;

use super::OneCoreBinding;
use super::common::SortDirection;
use crate::binding::mapper::deserialize_timestamp;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{TimestampFormat, into_id, into_timestamp};

#[uniffi::export(async_runtime = "tokio")]
impl OneCoreBinding {
    #[uniffi::method]
    pub async fn get_credential_schema(
        &self,
        credential_schema_id: String,
    ) -> Result<CredentialSchemaDetailBindingDTO, BindingError> {
        let credential_schema_id: CredentialSchemaId = into_id(&credential_schema_id)?;

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .get_credential_schema(&credential_schema_id)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn get_credential_schemas(
        &self,
        query: CredentialSchemaListQueryBindingDTO,
    ) -> Result<CredentialSchemaListBindingDTO, BindingError> {
        let organisation_id = into_id(&query.organisation_id)?;
        let sorting = query.sort.map(|sort_by| ListSorting {
            column: sort_by.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let mut conditions =
            vec![CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()];

        let exact = query.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        if let Some(name) = query.name.map(|name| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(
                    CredentialSchemaListQueryExactColumnBindingEnum::Name,
                ),
                value: name,
            })
        }) {
            conditions.push(name.condition())
        }

        if let Some(schema_id) = query.schema_id.map(|schema_id| {
            CredentialSchemaFilterValue::Name(StringMatch {
                r#match: get_string_match_type(
                    CredentialSchemaListQueryExactColumnBindingEnum::SchemaId,
                ),
                value: schema_id,
            })
        }) {
            conditions.push(schema_id.condition())
        }

        if let Some(formats) = query.formats.map(CredentialSchemaFilterValue::Formats) {
            conditions.push(formats.condition())
        }

        if let Some(ids) = query.ids {
            let ids = ids.iter().map(into_id).collect::<Result<_, _>>()?;
            conditions.push(CredentialSchemaFilterValue::CredentialSchemaIds(ids).condition());
        }

        if let Some(value) = query.created_date_after {
            conditions.push(
                CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }
        if let Some(value) = query.created_date_before {
            conditions.push(
                CredentialSchemaFilterValue::CreatedDate(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }
        if let Some(value) = query.last_modified_after {
            conditions.push(
                CredentialSchemaFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::GreaterThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }
        if let Some(value) = query.last_modified_before {
            conditions.push(
                CredentialSchemaFilterValue::LastModified(ValueComparison {
                    comparison: ComparisonType::LessThanOrEqual,
                    value: deserialize_timestamp(&value)?,
                })
                .condition(),
            );
        }

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .get_credential_schema_list(
                &organisation_id,
                GetCredentialSchemaQueryDTO {
                    pagination: Some(ListPagination {
                        page: query.page,
                        page_size: query.page_size,
                    }),
                    filtering: Some(ListFilterCondition::And(conditions)),
                    sorting,
                    include: query
                        .include
                        .map(|incl| incl.into_iter().map(Into::into).collect()),
                },
            )
            .await?
            .into())
    }

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

    #[uniffi::method]
    pub async fn import_credential_schema(
        &self,
        request: ImportCredentialSchemaRequestBindingDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .import_credential_schema(request)
            .await
            .map(|schema| schema.to_string())?)
    }

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
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaDetailResponseDTO)]
pub struct CredentialSchemaDetailBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub format: String,
    #[from(with_fn = inner_to_string)]
    pub revocation_method: Option<String>,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub requires_app_attestation: bool,
    #[from(with_fn = convert_inner)]
    pub transaction_code: Option<CredentialSchemaTransactionCodeBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, From)]
#[from(CredentialSchemaTransactionCodeDTO)]
pub struct CredentialSchemaTransactionCodeBindingDTO {
    pub r#type: TransactionCodeTypeBindingEnum,
    pub length: u32,
    pub description: Option<String>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: Option<String>,
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    pub schema_id: String,
    pub layout_type: Option<LayoutTypeBindingEnum>,
    pub imported_source_url: String,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    pub allow_suspension: bool,
    pub requires_app_attestation: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetCredentialSchemaListResponseDTO)]
pub struct CredentialSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<CredentialSchemaBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, uniffi::Record)]
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
    pub schema_id: Option<String>,
    pub formats: Option<Vec<String>>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
}

#[derive(Clone, Debug, PartialEq, uniffi::Enum)]
pub enum CredentialSchemaListQueryExactColumnBindingEnum {
    Name,
    SchemaId,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportCredentialSchemaRequestBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    pub schema: ImportCredentialSchemaRequestSchemaBindingDTO,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableCredentialSchemaColumn)]
pub enum SortableCredentialSchemaColumnBindingEnum {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialClaimSchemaDTO)]
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
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(LayoutType)]
#[into(LayoutType)]
pub enum LayoutTypeBindingEnum {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, From, TryInto, uniffi::Record)]
#[from(CredentialSchemaLayoutPropertiesResponseDTO)]
#[try_into(T=CredentialSchemaLayoutPropertiesRequestDTO, Error=ErrorResponseBindingDTO)]
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
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    #[try_into(infallible)]
    pub color: Option<String>,
    #[try_into(with_fn = try_convert_inner)]
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, TryInto, uniffi::Record)]
#[from(CredentialSchemaLogoPropertiesResponseDTO)]
#[try_into(T=CredentialSchemaLogoPropertiesRequestDTO, Error=ErrorResponseBindingDTO)]
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
pub struct CredentialSchemaCodePropertiesBindingDTO {
    pub attribute: String,
    pub r#type: CredentialSchemaCodeTypeBindingDTO,
}

#[derive(Clone, Debug, From, Into, uniffi::Enum)]
#[from(CredentialSchemaCodeTypeEnum)]
#[into(CredentialSchemaCodeTypeEnum)]
pub enum CredentialSchemaCodeTypeBindingDTO {
    Barcode,
    Mrz,
    QrCode,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(CredentialSchemaListIncludeEntityTypeEnum)]
pub enum CredentialSchemaListIncludeEntityType {
    LayoutProperties,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaRequestSchemaDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportCredentialSchemaRequestSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(infallible)]
    pub revocation_method: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(with_fn = try_convert_inner)]
    pub claims: Vec<ImportCredentialSchemaClaimSchemaBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible, with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub allow_suspension: Option<bool>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub requires_app_attestation: Option<bool>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub transaction_code: Option<ImportCredentialSchemaTransactionCodeBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record, Into)]
#[into(ImportCredentialSchemaTransactionCodeDTO)]
pub struct ImportCredentialSchemaTransactionCodeBindingDTO {
    pub r#type: TransactionCodeTypeBindingEnum,
    pub length: u32,
    pub description: Option<String>,
}

#[derive(From, Clone, Debug, Into, uniffi::Enum)]
#[from(TransactionCodeType)]
#[into(TransactionCodeType)]
pub enum TransactionCodeTypeBindingEnum {
    Numeric,
    Alphanumeric,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportCredentialSchemaClaimSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub required: bool,
    pub key: String,
    pub datatype: String,
    pub array: Option<bool>,
    pub claims: Option<Vec<ImportCredentialSchemaClaimSchemaBindingDTO>>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T=ImportCredentialSchemaLayoutPropertiesDTO, Error=ErrorResponseBindingDTO)]
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
pub enum KeyStorageSecurityBindingEnum {
    High,
    Moderate,
    EnhancedBasic,
    Basic,
}

fn inner_to_string(value: Option<impl ToString>) -> Option<String> {
    value.map(|inner| inner.to_string())
}
