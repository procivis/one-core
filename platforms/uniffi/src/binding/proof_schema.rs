use one_core::model::common::ExactColumn;
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::service::error::ServiceError;
use one_core::service::proof::dto::ProofClaimDTO;
use one_core::service::proof_schema::dto::{
    GetProofSchemaListItemDTO, GetProofSchemaListResponseDTO, GetProofSchemaResponseDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
    ProofSchemaShareResponseDTO,
};
use one_dto_mapper::{convert_inner, try_convert_inner, From, Into, TryInto};
use shared_types::ProofSchemaId;

use super::common::SortDirection;
use super::credential_schema::{
    CredentialSchemaBindingDTO, CredentialSchemaLayoutPropertiesBindingDTO,
    CredentialSchemaTypeBindingEnum, LayoutTypeBindingEnum, WalletStorageTypeBindingEnum,
};
use super::mapper::optional_time;
use super::OneCoreBinding;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{into_id, into_timestamp, TimestampFormat};

#[uniffi::export]
impl OneCoreBinding {
    #[uniffi::method]
    pub fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequestDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .create_proof_schema(request)
                .await?
                .to_string())
        })
    }

    #[uniffi::method]
    pub fn get_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<GetProofSchemaBindingDTO, BindingError> {
        let id: ProofSchemaId = into_id(&proof_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .get_proof_schema(&id)
                .await?
                .into())
        })
    }

    #[uniffi::method]
    pub fn get_proof_schemas(
        &self,
        filter: ListProofSchemasFiltersBindingDTO,
    ) -> Result<ProofSchemaListBindingDTO, BindingError> {
        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .get_proof_schema_list(filter.try_into()?)
                .await?
                .into())
        })
    }

    #[uniffi::method]
    pub fn share_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<ProofSchemaShareResponseBindingDTO, BindingError> {
        self.block_on(async {
            let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .share_proof_schema(proof_schema_id)
                .await?
                .into())
        })
    }

    #[uniffi::method]
    pub fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestBindingsDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .import_proof_schema(request)
                .await
                .map(|schema| schema.id.to_string())?)
        })
    }

    #[uniffi::method]
    pub fn delete_proof_schema(&self, proof_schema_id: String) -> Result<(), BindingError> {
        let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;

        self.block_on(async {
            let core = self.use_core().await?;
            Ok(core
                .proof_schema_service
                .delete_proof_schema(&proof_schema_id)
                .await?)
        })
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaListItemDTO)]
pub struct GetProofSchemaListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    #[from(with_fn = optional_time)]
    pub deleted_at: Option<String>,
    pub name: String,
    pub expire_duration: u32,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaRequestDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaRequestBindingsDTO {
    pub schema: ImportProofSchemaBindingDTO,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaResponseDTO)]
pub struct GetProofSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    pub expire_duration: u32,
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaBindingDTO>,
    #[from(with_fn = convert_inner)]
    pub imported_source_url: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputSchemaResponseDTO)]
pub struct ProofInputSchemaBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaInputSchemaDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaInputSchemaBindingDTO {
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaBindingDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaBindingDTO,
    #[try_into(infallible)]
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaCredentialSchemaDTO, Error = ErrorResponseBindingDTO)]
pub struct ImportProofSchemaCredentialSchemaBindingDTO {
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
    #[try_into(with_fn = convert_inner, infallible)]
    pub wallet_storage_type: Option<WalletStorageTypeBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(infallible)]
    pub schema_type: CredentialSchemaTypeBindingEnum,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ImportProofSchemaClaimSchemaBindingDTO {
    pub id: String,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub claims: Option<Vec<ImportProofSchemaClaimSchemaBindingDTO>>,
    pub array: bool,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofClaimDTO)]
pub struct ProofRequestClaimBindingDTO {
    pub schema: ProofClaimSchemaBindingDTO,
    #[from(with_fn = convert_inner)]
    pub value: Option<ProofRequestClaimValueBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofClaimSchemaResponseDTO)]
pub struct ProofClaimSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    #[from(with_fn = convert_inner)]
    pub claims: Vec<ProofClaimSchemaBindingDTO>,
    pub array: bool,
}

#[derive(Clone, Debug, uniffi::Enum)]
pub enum ProofRequestClaimValueBindingDTO {
    Value {
        value: String,
    },
    Claims {
        value: Vec<ProofRequestClaimBindingDTO>,
    },
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofSchemaShareResponseDTO)]
pub struct ProofSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaRequestDTO, Error = ServiceError)]
pub struct CreateProofSchemaRequestDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::ProofInputSchemaRequestDTO, Error = ServiceError)]
pub struct ProofInputSchemaRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_schema_id: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub validity_constraint: Option<i64>,
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaClaimRequestDTO, Error = ServiceError)]
pub struct CreateProofSchemaClaimRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(infallible)]
    pub required: bool,
}

#[derive(Clone, Debug, Into, PartialEq, uniffi::Enum)]
#[into(ExactColumn)]
pub enum ProofSchemaListQueryExactColumnBinding {
    Name,
}

#[derive(Clone, Debug, uniffi::Record)]
pub struct ListProofSchemasFiltersBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableProofSchemaColumnBinding>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub exact: Option<Vec<ProofSchemaListQueryExactColumnBinding>>,
    pub ids: Option<Vec<String>>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofSchemaColumn)]
pub enum SortableProofSchemaColumnBinding {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaListResponseDTO)]
pub struct ProofSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetProofSchemaListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}
