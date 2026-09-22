use one_dto_mapper::From;
use serde::Deserialize;
use shared_types::{
    ClaimSchemaId, CredentialFormat, CredentialSchemaId, EcosystemId, OrganisationId,
    ProofSchemaId, RevocationMethodId,
};
use time::OffsetDateTime;

use crate::model::common::GetListResponse;
use crate::model::credential_schema::KeyStorageSecurity;
use crate::model::list_filter::{ListFilterValue, StringMatch, ValueComparison};
use crate::model::proof_schema::{ExactProofSchemaFilterColumn, ProofSchema};
use crate::service::credential_schema::dto::{
    CredentialSchemaLayoutPropertiesRequestDTO, CredentialSchemaListItemResponseDTO,
};

pub type GetProofSchemaListResponseDTO = GetListResponse<GetProofSchemaListItemDTO>;

#[derive(Debug, Clone)]
pub enum ProofSchemaFilterValue {
    Name(StringMatch),
    OrganisationId(OrganisationId),
    ProofSchemaIds(Vec<ProofSchemaId>),
    Formats(Vec<String>),
    Ecosystems(Vec<EcosystemId>),
    CreatedDate(ValueComparison<OffsetDateTime>),
    LastModified(ValueComparison<OffsetDateTime>),
}

impl ListFilterValue for ProofSchemaFilterValue {}

#[derive(Clone, Debug)]
pub struct ProofSchemaFilterParamsDTO {
    pub name: Option<String>,
    pub exact: Option<Vec<ExactProofSchemaFilterColumn>>,
    pub organisation_id: OrganisationId,
    pub ids: Option<Vec<ProofSchemaId>>,
    pub formats: Option<Vec<String>>,
    pub ecosystems: Option<Vec<EcosystemId>>,
    pub created_date_after: Option<OffsetDateTime>,
    pub created_date_before: Option<OffsetDateTime>,
    pub last_modified_after: Option<OffsetDateTime>,
    pub last_modified_before: Option<OffsetDateTime>,
}

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
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaResponseDTO {
    pub formats: Vec<CredentialFormat>,
    pub claim_schemas: Vec<ProofClaimSchemaResponseDTO>,
    pub credential_schema: CredentialSchemaListItemResponseDTO,
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
    pub ecosystem: Option<EcosystemId>,
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
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct ProofInputSchemaRequestDTO {
    pub formats: Option<Vec<CredentialFormat>>,
    pub credential_schema_id: CredentialSchemaId,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaDTO {
    pub id: ProofSchemaId,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: OrganisationId,
    pub expire_duration: u32,
    pub proof_input_schemas: Vec<ImportProofSchemaInputSchemaDTO>,
    pub imported_source_url: String,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaInputSchemaDTO {
    pub formats: Option<Vec<CredentialFormat>>,
    #[serde(default)]
    pub claim_schemas: Vec<ImportProofSchemaClaimSchemaDTO>,
    pub credential_schema: ImportProofSchemaCredentialSchemaDTO,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaClaimSchemaDTO {
    pub id: ClaimSchemaId,
    pub requested: bool,
    pub required: bool,
    pub key: String,
    pub data_type: String,
    #[serde(default)]
    pub claims: Vec<ImportProofSchemaClaimSchemaDTO>,
    pub array: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImportProofSchemaCredentialSchemaDTO {
    pub id: CredentialSchemaId,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub created_date: OffsetDateTime,
    #[serde(deserialize_with = "time::serde::rfc3339::deserialize")]
    pub last_modified: OffsetDateTime,
    #[serde(
        default,
        deserialize_with = "time::serde::rfc3339::option::deserialize"
    )]
    pub deleted_at: Option<OffsetDateTime>,
    pub name: String,
    pub format: CredentialFormat,
    pub revocation_method: Option<RevocationMethodId>,
    pub key_storage_security: Option<KeyStorageSecurity>,
    pub schema_id: String,
    pub imported_source_url: String,
    pub layout_properties: Option<CredentialSchemaLayoutPropertiesRequestDTO>,
    pub allow_suspension: Option<bool>,
    pub requires_wallet_instance_attestation: Option<bool>,
    pub ecosystem: Option<EcosystemId>,
}

#[derive(Clone, Debug)]
pub struct ImportProofSchemaResponseDTO {
    pub id: ProofSchemaId,
}
