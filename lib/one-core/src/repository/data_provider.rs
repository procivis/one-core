// This is an old approach and will be slowly removed.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::{
    config::data_structure::{DatatypeEntity, ExchangeEntity},
    model::{
        common::{GetListQueryParams, GetListResponse},
        did::DidType,
    },
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
    pub issuer_did: Uuid,
    pub transport: String,
    pub claim_values: Vec<CreateCredentialRequestClaim>,
    pub receiver_did_id: Option<Uuid>,
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
pub struct CredentialShareResponse {
    pub credential_id: String,
    pub transport: String,
}

#[derive(Clone, Debug)]
pub struct ProofShareResponse {
    pub proof_id: String,
    pub transport: String,
}

#[derive(Clone, Debug)]
pub struct DetailCredentialResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub state: CredentialState,
    pub last_modified: OffsetDateTime,
    pub schema: ListCredentialSchemaResponse,
    pub issuer_did: Option<String>,
    pub claims: Vec<DetailCredentialClaimResponse>,
    pub credential: Vec<u8>,
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

#[derive(Clone, Debug)]
pub struct ProofDetailsResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub state: ProofRequestState,
    pub organisation_id: String,
    pub verifier_did: String,
    pub transport: String,
    pub receiver_did_id: Option<String>,
    pub claims: Vec<DetailProofClaim>,
    pub schema: DetailProofSchema,
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

#[derive(Clone, Debug)]
pub struct ProofsDetailResponse {
    pub id: String,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub issuance_date: OffsetDateTime,
    pub requested_date: Option<OffsetDateTime>,
    pub completed_date: Option<OffsetDateTime>,
    pub state: ProofRequestState,
    pub organisation_id: String,
    pub verifier_did: String,
    pub schema: DetailProofSchema,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SortableProofColumn {
    ProofSchemaName,
    VerifierDid,
    CreatedDate,
    State,
}

#[derive(Debug, PartialEq, Clone)]
pub enum ProofRequestState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Error,
}

#[derive(Clone, Debug)]
pub struct DetailCredentialClaimResponse {
    pub schema: CredentialClaimSchemaResponse,
    pub value: String,
}

#[derive(Debug, PartialEq, Clone)]
pub enum CredentialState {
    Created,
    Pending,
    Offered,
    Accepted,
    Rejected,
    Revoked,
    Error,
}

pub type GetProofsResponse = GetListResponse<ProofsDetailResponse>;
pub type GetCredentialsResponse = GetListResponse<DetailCredentialResponse>;
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
    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
        exchanges: &HashMap<String, ExchangeEntity>,
    ) -> Result<EntityResponse, DataLayerError>;

    async fn create_proof(
        &self,
        request: CreateProofRequest,
    ) -> Result<CreateProofResponse, DataLayerError>;

    async fn insert_remote_did(
        &self,
        did_value: &str,
        organisation_id: &str,
    ) -> Result<String, DataLayerError>;

    async fn get_credential_details(
        &self,
        uuid: &str,
    ) -> Result<DetailCredentialResponse, DataLayerError>;

    async fn get_credentials(
        &self,
        query_params: GetCredentialsQuery,
    ) -> Result<GetCredentialsResponse, DataLayerError>;

    async fn get_proof_details(&self, uuid: &str) -> Result<ProofDetailsResponse, DataLayerError>;

    async fn get_proofs(
        &self,
        query_params: GetProofsQuery,
    ) -> Result<GetProofsResponse, DataLayerError>;

    async fn reject_proof_request(&self, proof_request_id: &str) -> Result<(), DataLayerError>;

    async fn set_credential_state(
        &self,
        credential_id: &str,
        new_state: CredentialState,
    ) -> Result<(), DataLayerError>;

    async fn share_credential(
        &self,
        credential_id: &str,
    ) -> Result<CredentialShareResponse, DataLayerError>;

    async fn share_proof(&self, proof_id: &str) -> Result<ProofShareResponse, DataLayerError>;

    async fn update_credential_issuer_did(
        &self,
        credential_id: &str,
        issuer: &str,
    ) -> Result<(), DataLayerError>;

    async fn update_credential_received_did(
        &self,
        credential_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError>;

    async fn update_credential_token(
        &self,
        credential_id: &str,
        token: Vec<u8>,
    ) -> Result<(), DataLayerError>;

    async fn get_all_credentials(&self) -> Result<Vec<DetailCredentialResponse>, DataLayerError>;

    async fn set_proof_receiver_did_id(
        &self,
        proof_request_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError>;

    async fn get_local_dids(
        &self,
        organisation_id: &str,
    ) -> Result<Vec<GetDidDetailsResponse>, DataLayerError>;

    async fn set_proof_state(
        &self,
        proof_request_id: &str,
        state: ProofRequestState,
    ) -> Result<(), DataLayerError>;

    async fn set_proof_claims(
        &self,
        proof_request_id: &str,
        claims: Vec<CreateProofClaimRequest>,
    ) -> Result<(), DataLayerError>;
}
