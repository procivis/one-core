use migration::{Migrator, MigratorTrait};
use organisation::OrganisationProvider;
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;

use one_core::{
    config::data_structure::DatatypeEntity,
    repository::{
        data_provider::{
            CreateCredentialRequest, CreateCredentialSchemaFromJwtRequest,
            CreateCredentialSchemaRequest, CreateCredentialSchemaResponse, CreateDidRequest,
            CreateDidResponse, CreateProofClaimRequest, CreateProofRequest, CreateProofResponse,
            CreateProofSchemaRequest, CreateProofSchemaResponse, CredentialSchemaResponse,
            CredentialShareResponse, CredentialState, DataProvider, DetailCredentialResponse,
            EntityResponse, GetCredentialClaimSchemaResponse, GetCredentialSchemaQuery,
            GetCredentialsQuery, GetCredentialsResponse, GetDidDetailsResponse, GetDidQuery,
            GetDidsResponse, GetProofSchemaQuery, GetProofSchemaResponse, GetProofsQuery,
            GetProofsResponse, ProofDetailsResponse, ProofRequestState, ProofSchemaResponse,
            ProofShareResponse,
        },
        error::DataLayerError,
        organisation_repository::OrganisationRepository,
        DataRepository,
    },
};

mod common;
mod common_queries;
mod create_credential;
mod create_credential_schema;
mod create_credential_schema_from_jwt;
mod create_did;
mod create_proof;
mod create_proof_schema;
mod data_model;
mod delete_credential_schema;
mod delete_proof_schema;
mod did_manipulation;
mod entity;
mod get_credential_details;
mod get_credential_schema_details;
mod get_credential_schemas;
mod get_credentials;
mod get_did;
mod get_dids;
mod get_local_dids;
mod get_proof_details;
mod get_proof_schema_details;
mod get_proof_schemas;
mod get_proofs;
mod reject_proof_request;
mod set_credential_state;
mod share_credential;
mod share_proof;
mod update_credential;
mod update_proof;

mod list_query;

pub mod organisation;

mod error_mapper;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(unused)]
    db: DatabaseConnection,
    data_provider: Arc<dyn DataProvider + Send + Sync>, // FIXME to be removed
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
}

impl DataLayer {
    pub async fn create(database_url: &str) -> Self {
        let db = sea_orm::Database::connect(database_url)
            .await
            .expect("Database Connected");

        Migrator::up(&db, None).await.unwrap();

        Self {
            data_provider: Arc::new(OldProvider { db: db.clone() }),
            organisation_repository: Arc::new(OrganisationProvider { db: db.clone() }),
            db,
        }
    }
}

#[async_trait::async_trait]
impl DataRepository for DataLayer {
    fn get_data_provider(&self) -> Arc<dyn DataProvider + Send + Sync> {
        self.data_provider.clone()
    }
    fn get_organisation_repository(&self) -> Arc<dyn OrganisationRepository + Send + Sync> {
        self.organisation_repository.clone()
    }
}

pub(crate) struct OldProvider {
    pub db: DatabaseConnection,
}

#[async_trait::async_trait]
impl DataProvider for OldProvider {
    async fn create_credential_schema_from_jwt(
        &self,
        request: CreateCredentialSchemaFromJwtRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<CreateCredentialSchemaResponse, DataLayerError> {
        self.create_credential_schema_from_jwt(request, datatypes)
            .await
    }

    async fn set_proof_receiver_did_id(
        &self,
        proof_request_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError> {
        self.set_proof_receiver_did_id(proof_request_id, did_id)
            .await
    }

    async fn share_proof(&self, proof_id: &str) -> Result<ProofShareResponse, DataLayerError> {
        self.share_proof(proof_id).await
    }

    async fn create_proof(
        &self,
        request: CreateProofRequest,
    ) -> Result<CreateProofResponse, DataLayerError> {
        self.create_proof(request).await
    }

    async fn get_proofs(
        &self,
        query_params: GetProofsQuery,
    ) -> Result<GetProofsResponse, DataLayerError> {
        self.get_proofs(query_params).await
    }

    async fn reject_proof_request(&self, proof_request_id: &str) -> Result<(), DataLayerError> {
        self.reject_proof_request(proof_request_id).await
    }

    async fn create_credential_schema(
        &self,
        request: CreateCredentialSchemaRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<CreateCredentialSchemaResponse, DataLayerError> {
        self.create_credential_schema(request, datatypes).await
    }

    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
    ) -> Result<EntityResponse, DataLayerError> {
        self.create_credential(request, datatypes).await
    }

    async fn create_did(
        &self,
        request: CreateDidRequest,
    ) -> Result<CreateDidResponse, DataLayerError> {
        self.create_did(request).await
    }

    async fn create_proof_schema(
        &self,
        request: CreateProofSchemaRequest,
    ) -> Result<CreateProofSchemaResponse, DataLayerError> {
        self.create_proof_schema(request).await
    }

    async fn delete_credential_schema(&self, id: &str) -> Result<(), DataLayerError> {
        self.delete_credential_schema(id).await
    }

    async fn delete_proof_schema(&self, id: &str) -> Result<(), DataLayerError> {
        self.delete_proof_schema(id).await
    }

    async fn insert_remote_did(
        &self,
        did_value: &str,
        organisation_id: &str,
    ) -> Result<String, DataLayerError> {
        self.insert_remote_did(did_value, organisation_id).await
    }

    async fn get_credential_details(
        &self,
        uuid: &str,
    ) -> Result<DetailCredentialResponse, DataLayerError> {
        self.get_credential_details(uuid).await
    }

    async fn get_credential_schema_details(
        &self,
        uuid: &str,
    ) -> Result<CredentialSchemaResponse, DataLayerError> {
        self.get_credential_schema_details(uuid).await
    }

    async fn get_credential_schemas(
        &self,
        query_params: GetCredentialSchemaQuery,
    ) -> Result<GetCredentialClaimSchemaResponse, DataLayerError> {
        self.get_credential_schemas(query_params).await
    }

    async fn get_proof_details(&self, uuid: &str) -> Result<ProofDetailsResponse, DataLayerError> {
        self.get_proof_details(uuid).await
    }

    async fn get_credentials(
        &self,
        query_params: GetCredentialsQuery,
    ) -> Result<GetCredentialsResponse, DataLayerError> {
        self.get_credentials(query_params).await
    }

    async fn get_all_credentials(&self) -> Result<Vec<DetailCredentialResponse>, DataLayerError> {
        self.get_all_credentials().await
    }

    async fn get_did_details_by_value(
        &self,
        value: &str,
    ) -> Result<GetDidDetailsResponse, DataLayerError> {
        self.get_did_details_by_value(value).await
    }

    async fn get_did_details(&self, uuid: &str) -> Result<GetDidDetailsResponse, DataLayerError> {
        self.get_did_details(uuid).await
    }

    async fn get_dids(&self, query_params: GetDidQuery) -> Result<GetDidsResponse, DataLayerError> {
        self.get_dids(query_params).await
    }

    async fn get_proof_schema_details(
        &self,
        uuid: &str,
    ) -> Result<ProofSchemaResponse, DataLayerError> {
        self.get_proof_schema_details(uuid).await
    }

    async fn get_proof_schemas(
        &self,
        query_params: GetProofSchemaQuery,
    ) -> Result<GetProofSchemaResponse, DataLayerError> {
        self.get_proof_schemas(query_params).await
    }

    async fn set_credential_state(
        &self,
        credential_id: &str,
        new_state: CredentialState,
    ) -> Result<(), DataLayerError> {
        self.set_credential_state(credential_id, new_state).await
    }

    async fn share_credential(
        &self,
        credential_id: &str,
    ) -> Result<CredentialShareResponse, DataLayerError> {
        self.share_credential(credential_id).await
    }

    async fn update_credential_issuer_did(
        &self,
        credential_id: &str,
        issuer: &str,
    ) -> Result<(), DataLayerError> {
        self.update_credential_issuer_did(credential_id, issuer)
            .await
    }

    async fn update_credential_received_did(
        &self,
        credential_id: &str,
        did_id: &str,
    ) -> Result<(), DataLayerError> {
        self.update_credential_received_did(credential_id, did_id)
            .await
    }

    async fn update_credential_token(
        &self,
        credential_id: &str,
        token: Vec<u8>,
    ) -> Result<(), DataLayerError> {
        self.update_credential_token(credential_id, token).await
    }

    async fn get_local_dids(
        &self,
        organisation_id: &str,
    ) -> Result<Vec<GetDidDetailsResponse>, DataLayerError> {
        self.get_local_dids(organisation_id).await
    }

    async fn set_proof_state(
        &self,
        proof_request_id: &str,
        state: ProofRequestState,
    ) -> Result<(), DataLayerError> {
        self.set_proof_state(proof_request_id, state).await
    }

    async fn set_proof_claims(
        &self,
        proof_request_id: &str,
        claims: Vec<CreateProofClaimRequest>,
    ) -> Result<(), DataLayerError> {
        self.set_proof_claims(proof_request_id, claims).await
    }
}

#[cfg(test)]
pub(crate) mod test_utilities;
