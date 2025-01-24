use one_core::model::common::ExactColumn;
use one_core::model::credential_schema::{
    LayoutType, SortableCredentialSchemaColumn, WalletStorageTypeEnum,
};
use one_core::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use one_core::model::list_query::{ListPagination, ListSorting};
use one_core::service::credential_schema::dto::{
    CredentialClaimSchemaDTO, CredentialSchemaBackgroundPropertiesRequestDTO,
    CredentialSchemaCodePropertiesRequestDTO, CredentialSchemaCodeTypeEnum,
    CredentialSchemaDetailResponseDTO, CredentialSchemaFilterValue,
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaListIncludeEntityTypeEnum,
    CredentialSchemaLogoPropertiesRequestDTO, CredentialSchemaShareResponseDTO,
    GetCredentialSchemaListResponseDTO, GetCredentialSchemaQueryDTO,
    ImportCredentialSchemaLayoutPropertiesDTO, ImportCredentialSchemaRequestDTO,
    ImportCredentialSchemaRequestSchemaDTO,
};
use one_core::service::error::ServiceError;
use one_dto_mapper::{convert_inner, try_convert_inner, From, Into, TryInto};
use shared_types::CredentialSchemaId;

use super::common::SortDirection;
use super::OneCoreBinding;
use crate::error::BindingError;
use crate::utils::{into_id, into_timestamp, TimestampFormat};

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
        let sorting = query.sort.map(|sort_by| ListSorting {
            column: sort_by.into(),
            direction: query.sort_direction.map(Into::into),
        });

        let mut conditions =
            vec![
                CredentialSchemaFilterValue::OrganisationId(into_id(&query.organisation_id)?)
                    .condition(),
            ];

        if let Some(name) = query.name {
            let name_filter = if query
                .exact
                .is_some_and(|e| e.contains(&CredentialSchemaListQueryExactColumnBindingEnum::Name))
            {
                StringMatch::equals(name)
            } else {
                StringMatch::starts_with(name)
            };

            conditions.push(CredentialSchemaFilterValue::Name(name_filter).condition())
        }

        if let Some(ids) = query.ids {
            let ids = ids.iter().map(|id| into_id(id)).collect::<Result<_, _>>()?;
            conditions.push(CredentialSchemaFilterValue::CredentialSchemaIds(ids).condition());
        }

        let core = self.use_core().await?;
        Ok(core
            .credential_schema_service
            .get_credential_schema_list(GetCredentialSchemaQueryDTO {
                pagination: Some(ListPagination {
                    page: query.page,
                    page_size: query.page_size,
                }),
                filtering: Some(ListFilterCondition::And(conditions)),
                sorting,
                include: query
                    .include
                    .map(|incl| incl.into_iter().map(Into::into).collect()),
            })
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
    pub format: String,
    pub revocation_method: String,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<CredentialClaimSchemaBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaTypeBindingEnum,
    pub imported_source_url: String,
    #[from(with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[from(with_fn = convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct CredentialSchemaBindingDTO {
    pub id: String,
    pub created_date: String,
    pub last_modified: String,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    pub schema_id: String,
    pub schema_type: CredentialSchemaTypeBindingEnum,
    pub layout_type: Option<LayoutTypeBindingEnum>,
    pub imported_source_url: String,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
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
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactColumn)]
pub enum CredentialSchemaListQueryExactColumnBindingEnum {
    Name,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(CredentialSchemaShareResponseDTO)]
pub struct CredentialSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportCredentialSchemaRequestDTO, Error = ServiceError)]
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

#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum CredentialSchemaTypeBindingEnum {
    ProcivisOneSchema2024 {},
    FallbackSchema2024 {},
    Mdoc {},
    Other { value: String },
}

#[derive(Clone, Debug, Eq, PartialEq, From, Into, uniffi::Enum)]
#[from(LayoutType)]
#[into(LayoutType)]
pub enum LayoutTypeBindingEnum {
    Card,
    Document,
    SingleAttribute,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaLayoutPropertiesRequestDTO)]
#[into(CredentialSchemaLayoutPropertiesRequestDTO)]
pub struct CredentialSchemaLayoutPropertiesBindingDTO {
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[from(with_fn = convert_inner)]
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaBackgroundPropertiesRequestDTO)]
#[into(CredentialSchemaBackgroundPropertiesRequestDTO)]
pub struct CredentialSchemaBackgroundPropertiesBindingDTO {
    pub color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaLogoPropertiesRequestDTO)]
#[into(CredentialSchemaLogoPropertiesRequestDTO)]
pub struct CredentialSchemaLogoPropertiesBindingDTO {
    pub font_color: Option<String>,
    pub background_color: Option<String>,
    pub image: Option<String>,
}

#[derive(Clone, Debug, From, Into, uniffi::Record)]
#[from(CredentialSchemaCodePropertiesRequestDTO)]
#[into(CredentialSchemaCodePropertiesRequestDTO)]
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
#[try_into(T = ImportCredentialSchemaRequestSchemaDTO, Error = ServiceError)]
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
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaTypeBindingEnum,
    #[try_into(infallible, with_fn = convert_inner)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub layout_properties: Option<ImportCredentialSchemaLayoutPropertiesBindingDTO>,
    #[try_into(infallible, with_fn = convert_inner)]
    pub allow_suspension: Option<bool>,
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

#[derive(Clone, Debug, Into, uniffi::Record)]
#[into(ImportCredentialSchemaLayoutPropertiesDTO)]
pub struct ImportCredentialSchemaLayoutPropertiesBindingDTO {
    #[into(with_fn = convert_inner)]
    pub background: Option<CredentialSchemaBackgroundPropertiesBindingDTO>,
    #[into(with_fn = convert_inner)]
    pub logo: Option<CredentialSchemaLogoPropertiesBindingDTO>,
    pub primary_attribute: Option<String>,
    pub secondary_attribute: Option<String>,
    pub picture_attribute: Option<String>,
    #[into(with_fn = convert_inner)]
    pub code: Option<CredentialSchemaCodePropertiesBindingDTO>,
}

#[derive(From, Clone, Debug, Into, uniffi::Enum)]
#[from(WalletStorageTypeEnum)]
#[into(WalletStorageTypeEnum)]
pub enum WalletStorageTypeBindingEnum {
    Hardware,
    Software,
}
