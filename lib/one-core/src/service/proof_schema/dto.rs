use one_dto_mapper::From;
use serde::Deserialize;
use shared_types::{ClaimSchemaId, CredentialSchemaId, OrganisationId, ProofSchemaId};
use time::OffsetDateTime;

use crate::model::common::{GetListQueryParams, GetListResponse};
use crate::model::credential_schema::{
    CredentialFormat, LayoutType, RevocationMethod, WalletStorageTypeEnum,
};
use crate::model::proof_schema::{ProofSchema, SortableProofSchemaColumn};
use crate::service::credential::dto::CredentialSchemaType;
use crate::service::credential_schema::dto::{
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaListItemResponseDTO,
};

pub type GetProofSchemaListResponseDTO = GetListResponse<GetProofSchemaListItemDTO>;
pub type GetProofSchemaQueryDTO = GetListQueryParams<SortableProofSchemaColumn>;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProofClaimSchemaResponseDTO {
    pub id: ClaimSchemaId,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    #[serde(default)]
    pub claims: Vec<ProofClaimSchemaResponseDTO>,
    pub array: bool,
}

#[derive(Clone, Debug)]
pub struct GetProofSchemaResponseDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub imported_source_url: Option<String>,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub proof_input_schemas: Vec<ProofInputSchemaResponseDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaResponseDTO {
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug, From)]
#[from(ProofSchema)]
pub struct GetProofSchemaListItemDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub expire_duration: u32,
}

#[derive(Clone, Debug)]
pub struct CreateProofSchemaClaimRequestDTO {
    pub id: ClaimSchemaId,
    pub required: bool,
}

#[derive(Clone, Debug)]
pub struct CreateProofSchemaRequestDTO {
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: Option<u32>,
    pub proof_input_schemas: Vec<ProofInputSchemaRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaRequestDTO {
    pub credential_schema_id: CredentialSchemaId,
    pub validity_constraint: Option<i64>,
    pub claim_schemas: Vec<CreateProofSchemaClaimRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct ProofSchemaShareResponseDTO {
    pub url: String,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaRequestDTO {
    pub schema: ImportProofSchemaDTO,
    pub organisation_id: OrganisationId,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaDTO {
    pub id: ProofSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaDTO>,
    pub imported_source_url: String,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaInputSchemaDTO {
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaDTO,
    pub validity_constraint: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaClaimSchemaDTO {
    pub id: ClaimSchemaId,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    pub claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    pub array: bool,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaCredentialSchemaDTO {
    pub id: CredentialSchemaId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: RevocationMethod,
    pub wallet_storage_type: Option<WalletStorageTypeEnum>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub schema_type: CredentialSchemaType,
    pub layout_type: Option<LayoutType>,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaResponseDTO {
    pub id: ProofSchemaId,
}
