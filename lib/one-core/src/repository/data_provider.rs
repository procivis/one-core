// This is an old approach and will be slowly removed.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::model::{
    common::{GetListQueryParams, GetListResponse},
    did::DidType,
};

use super::error::DataLayerError;

#[derive(Clone, Debug)]
pub struct CredentialClaimSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub key: String,
    pub datatype: String,
}

#[derive(Clone, Debug)]
pub struct CredentialSchemaResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: String,
    pub claims: Vec<CredentialClaimSchemaResponse>,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialRequest {
    pub credential_id: Option<String>,
    pub credential_schema_id: Uuid,
    pub issuer_did_id: Uuid,
    pub transport: String,
    pub claim_values: Vec<CreateCredentialRequestClaim>,
    pub holder_did_id: Option<Uuid>,
    pub credential: Option<Vec<u8>>,
}

#[derive(Clone, Debug)]
pub struct CreateProofClaimRequest {
    pub claim_schema_id: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct CreateCredentialRequestClaim {
    pub claim_id: Uuid,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct EntityResponse {
    pub id: String,
}

#[derive(Clone, Debug)]
pub struct GetDidDetailsResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub organisation_id: String,
    pub did: String,
    pub did_type: DidType,
    pub did_method: String,
}

#[derive(Clone, Debug)]
pub struct ProofShareResponse {
    pub proof_id: String,
    pub transport: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")] // serialization necessary for wallet to parse JSON API response
pub struct ListCredentialSchemaResponse {
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_date: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub last_modified: OffsetDateTime,
    pub name: String,
    pub format: String,
    pub revocation_method: String,
    pub organisation_id: String,
}

#[derive(Debug, Clone)]
pub struct DetailProofSchema {
    pub id: String,
    pub name: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub organisation_id: String,
}

#[derive(Debug, Clone)]
pub struct DetailProofClaim {
    pub schema: DetailProofClaimSchema,
    pub value: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DetailProofClaimSchema {
    pub id: String,
    pub key: String,
    pub datatype: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub credential_schema: ListCredentialSchemaResponse,
}

#[derive(Clone, Debug)]
pub struct CreateProofRequest {
    pub proof_schema_id: Uuid,
    pub verifier_did_id: Uuid,
    pub transport: String,
}

#[derive(Clone, Debug)]
pub struct CreateProofResponse {
    pub id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofColumn {
    ProofSchemaName,
    VerifierDid,
    CreatedDate,
    State,
}

#[derive(Clone, Debug)]
pub struct DetailCredentialClaimResponse {
    pub schema: CredentialClaimSchemaResponse,
    pub value: String,
}

pub type GetCredentialClaimSchemaResponse = GetListResponse<CredentialSchemaResponse>;

pub type GetProofsQuery = GetListQueryParams<SortableProofColumn>;
pub type GetCredentialSchemaQuery = GetListQueryParams<SortableCredentialSchemaColumn>;
pub type GetCredentialsQuery = GetListQueryParams<SortableCredentialColumn>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Transport {
    ProcivisTemporary,
    OpenId4Vc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialSchemaColumn {
    Name,
    Format,
    CreatedDate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableCredentialColumn {
    CreatedDate,
    SchemaName,
    IssuerDid,
    State,
}

#[async_trait::async_trait]
pub trait DataProvider {
    async fn insert_remote_did(
        &self,
        did_value: &str,
        organisation_id: &str,
    ) -> Result<String, DataLayerError>;

    async fn update_credential_issuer_did(
        &self,
        credential_id: &str,
        issuer: &str,
    ) -> Result<(), DataLayerError>;

    async fn update_credential_holder_did(
        &self,
        credential_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError>;

    async fn update_credential_token(
        &self,
        credential_id: &str,
        token: Vec<u8>,
    ) -> Result<(), DataLayerError>;

    async fn get_local_dids(
        &self,
        organisation_id: &str,
    ) -> Result<Vec<GetDidDetailsResponse>, DataLayerError>;
}
