use one_core::model::common::ExactColumn;
use one_core::model::proof_schema::SortableProofSchemaColumn;
use one_core::service::error::ServiceError;
use one_core::service::proof_schema::dto::{
    GetProofSchemaListItemDTO, GetProofSchemaListResponseDTO, GetProofSchemaResponseDTO,
    ImportProofSchemaCredentialSchemaDTO, ImportProofSchemaDTO, ImportProofSchemaInputSchemaDTO,
    ImportProofSchemaRequestDTO, ProofClaimSchemaResponseDTO, ProofInputSchemaResponseDTO,
    ProofSchemaShareResponseDTO,
};
use one_dto_mapper::{From, Into, TryInto, convert_inner, try_convert_inner};
use shared_types::ProofSchemaId;

use super::OneCore;
use super::common::SortDirection;
use super::credential_schema::{
    CredentialSchemaBindingDTO, CredentialSchemaLayoutPropertiesBindingDTO,
    KeyStorageSecurityBindingEnum, LayoutTypeBindingEnum,
};
use super::mapper::optional_time;
use crate::error::{BindingError, ErrorResponseBindingDTO};
use crate::utils::{TimestampFormat, into_id, into_timestamp, into_timestamp_opt};

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Creates a proof schema, which defines the credentials and claims to
    /// request from a wallet. Proof schemas reference credential schemas
    /// already created in your own system; create or import those first
    /// before building a proof schema that includes their claims.
    #[uniffi::method]
    pub async fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequestDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .create_proof_schema(request)
            .await?
            .to_string())
    }

    #[uniffi::method]
    pub async fn get_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<GetProofSchemaBindingDTO, BindingError> {
        let id: ProofSchemaId = into_id(&proof_schema_id)?;

        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .get_proof_schema(&id)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn list_proof_schemas(
        &self,
        filter: ListProofSchemasFiltersBindingDTO,
    ) -> Result<ProofSchemaListBindingDTO, BindingError> {
        let organisation_id = into_id(filter.organisation_id.clone())?;
        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .get_proof_schema_list(&organisation_id, filter.try_into()?)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn share_proof_schema(
        &self,
        proof_schema_id: String,
    ) -> Result<ProofSchemaShareResponseBindingDTO, BindingError> {
        let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;
        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .share_proof_schema(proof_schema_id)
            .await?
            .into())
    }

    #[uniffi::method]
    pub async fn import_proof_schema(
        &self,
        request: ImportProofSchemaRequestBindingsDTO,
    ) -> Result<String, BindingError> {
        let request = request.try_into()?;

        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .import_proof_schema(request)
            .await
            .map(|schema| schema.id.to_string())?)
    }

    #[uniffi::method]
    pub async fn delete_proof_schema(&self, proof_schema_id: String) -> Result<(), BindingError> {
        let proof_schema_id: ProofSchemaId = into_id(&proof_schema_id)?;

        let core = self.use_core().await?;
        Ok(core
            .proof_schema_service
            .delete_proof_schema(&proof_schema_id)
            .await?)
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaListItemDTO)]
#[uniffi(name = "ProofSchemaListItem")]
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
    /// Defines how long the system will store data received from wallets. After
    /// the defined duration, the received proof and its data are deleted from
    /// the system. If 0, proofs received when using this schema will not be
    /// deleted.
    pub expire_duration: u32,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaRequestDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportProofSchemaRequest")]
pub struct ImportProofSchemaRequestBindingsDTO {
    pub schema: ImportProofSchemaBindingDTO,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportProofSchema")]
pub struct ImportProofSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(infallible)]
    pub name: String,
    /// Specifies the organizational context for this operation.
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    /// Defines how long the system will store data received from wallets. After
    /// the defined duration, the received proof and its data are deleted from
    /// the system. If 0, proofs received when using this schema will not be
    /// deleted.
    #[try_into(infallible)]
    pub expire_duration: u32,
    #[try_into(infallible)]
    pub imported_source_url: String,
    /// Set of all claims to request.
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaBindingDTO>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaResponseDTO)]
#[uniffi(name = "ProofSchemaDetail")]
pub struct GetProofSchemaBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    /// Specifies organizational context for this operation.
    #[from(with_fn_ref = "ToString::to_string")]
    pub organisation_id: String,
    /// Defines how long the system will store data received from wallets. After
    /// the defined duration, the received proof and its data are deleted from
    /// the system. If 0, proofs received when using this schema will not be
    /// deleted.
    pub expire_duration: u32,
    /// Set of requested claims.
    #[from(with_fn = convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaBindingDTO>,
    /// Source URL for imported schema.
    #[from(with_fn = convert_inner)]
    pub imported_source_url: Option<String>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofInputSchemaResponseDTO)]
#[uniffi(name = "ProofInputSchema")]
pub struct ProofInputSchemaBindingDTO {
    #[from(with_fn = convert_inner)]
    pub claim_schemas: Vec<ProofClaimSchemaBindingDTO>,
    pub credential_schema: CredentialSchemaBindingDTO,
}

#[derive(Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaInputSchemaDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportProofSchemaInputSchema")]
pub struct ImportProofSchemaInputSchemaBindingDTO {
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaBindingDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaBindingDTO,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = ImportProofSchemaCredentialSchemaDTO, Error = ErrorResponseBindingDTO)]
#[uniffi(name = "ImportProofSchemaCredentialSchema")]
pub struct ImportProofSchemaCredentialSchemaBindingDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub created_date: String,
    #[try_into(with_fn_ref = into_timestamp)]
    pub last_modified: String,
    #[try_into(with_fn = into_timestamp_opt)]
    pub deleted_at: Option<String>,
    #[try_into(infallible)]
    pub name: String,
    #[try_into(infallible)]
    pub format: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub revocation_method: Option<String>,
    #[try_into(with_fn = convert_inner, infallible)]
    pub key_storage_security: Option<KeyStorageSecurityBindingEnum>,
    #[try_into(infallible)]
    pub schema_id: String,
    #[try_into(infallible)]
    pub imported_source_url: String,
    #[try_into(with_fn = convert_inner, infallible)]
    pub layout_type: Option<LayoutTypeBindingEnum>,
    #[try_into(with_fn = try_convert_inner)]
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesBindingDTO>,
    #[try_into(infallible)]
    pub allow_suspension: Option<bool>,
    #[try_into(infallible)]
    pub requires_wallet_instance_attestation: Option<bool>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ImportProofSchemaClaimSchema")]
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
#[from(ProofClaimSchemaResponseDTO)]
#[uniffi(name = "ProofClaimSchema")]
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

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(ProofSchemaShareResponseDTO)]
#[uniffi(name = "ProofSchemaShareResponse")]
pub struct ProofSchemaShareResponseBindingDTO {
    pub url: String,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaRequestDTO, Error = ServiceError)]
#[uniffi(name = "CreateProofSchemaRequest")]
pub struct CreateProofSchemaRequestDTO {
    #[try_into(infallible)]
    pub name: String,
    #[try_into(with_fn_ref = into_id)]
    pub organisation_id: String,
    #[try_into(infallible)]
    pub expire_duration: u32,
    /// Set of all claims to request.
    #[try_into(with_fn = try_convert_inner)]
    pub proof_input_schemas: Vec<ProofInputSchemaRequestDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::ProofInputSchemaRequestDTO, Error = ServiceError)]
#[uniffi(name = "CreateProofSchemaInput")]
pub struct ProofInputSchemaRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub credential_schema_id: String,
    #[try_into(with_fn = try_convert_inner)]
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Clone, Debug, TryInto, uniffi::Record)]
#[try_into(T = one_core::service::proof_schema::dto::CreateProofSchemaClaimRequestDTO, Error = ServiceError)]
#[uniffi(name = "CreateProofSchemaInputClaim")]
pub struct CreateProofSchemaClaimRequestDTO {
    #[try_into(with_fn_ref = into_id)]
    pub id: String,
    #[try_into(infallible)]
    pub required: bool,
}

#[derive(Clone, Debug, Into, PartialEq, uniffi::Enum)]
#[into(ExactColumn)]
#[uniffi(name = "ProofSchemaListQueryExactColumn")]
pub enum ProofSchemaListQueryExactColumnBinding {
    Name,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "ProofSchemaListQuery")]
pub struct ListProofSchemasFiltersBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableProofSchemaColumnBinding>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub exact: Option<Vec<ProofSchemaListQueryExactColumnBinding>>,
    pub ids: Option<Vec<String>>,
    pub formats: Option<Vec<String>>,

    pub created_date_after: Option<String>,
    pub created_date_before: Option<String>,
    pub last_modified_after: Option<String>,
    pub last_modified_before: Option<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableProofSchemaColumn)]
#[uniffi(name = "SortableProofSchemaColumn")]
pub enum SortableProofSchemaColumnBinding {
    Name,
    CreatedDate,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetProofSchemaListResponseDTO)]
#[uniffi(name = "ProofSchemaList")]
pub struct ProofSchemaListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<GetProofSchemaListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}
