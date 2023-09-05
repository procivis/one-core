use crate::credential_schema::CredentialSchemaProvider;
use claim::ClaimProvider;
use claim_schema::ClaimSchemaProvider;
use did::DidProvider;
use migration::{Migrator, MigratorTrait};
use one_core::repository::credential_schema_repository::CredentialSchemaRepository;
use one_core::{
    config::data_structure::{DatatypeEntity, ExchangeEntity},
    repository::{
        claim_repository::ClaimRepository,
        claim_schema_repository::ClaimSchemaRepository,
        data_provider::{
            CreateCredentialRequest, CreateProofClaimRequest, CreateProofRequest,
            CreateProofResponse, CredentialShareResponse, CredentialState, DataProvider,
            DetailCredentialResponse, EntityResponse, GetCredentialsQuery, GetCredentialsResponse,
            GetDidDetailsResponse, GetProofsQuery, GetProofsResponse, ProofDetailsResponse,
            ProofRequestState, ProofShareResponse,
        },
        did_repository::DidRepository,
        error::DataLayerError,
        organisation_repository::OrganisationRepository,
        proof_schema_repository::ProofSchemaRepository,
        DataRepository,
    },
};
use organisation::OrganisationProvider;
use proof_schema::ProofSchemaProvider;
use sea_orm::DatabaseConnection;
use std::collections::HashMap;
use std::sync::Arc;

mod common;
mod common_queries;
mod create_credential;
mod create_proof;
mod data_model;
mod did_manipulation;
mod entity;
mod get_credential_details;
mod get_credentials;
mod get_local_dids;
mod get_proof_details;
mod get_proofs;
mod reject_proof_request;
mod set_credential_state;
mod share_credential;
mod share_proof;
mod update_credential;
mod update_proof;

mod list_query;

// New implementations
pub mod claim;
pub mod claim_schema;
pub mod credential_schema;
pub mod did;
pub mod organisation;
pub mod proof_schema;

mod error_mapper;

#[derive(Clone)]
pub struct DataLayer {
    // Used for tests for now
    #[allow(unused)]
    db: DatabaseConnection,
    data_provider: Arc<dyn DataProvider + Send + Sync>, // FIXME to be removed
    organisation_repository: Arc<dyn OrganisationRepository + Send + Sync>,
    did_repository: Arc<dyn DidRepository + Send + Sync>,
    claim_repository: Arc<dyn ClaimRepository + Send + Sync>,
    claim_schema_repository: Arc<dyn ClaimSchemaRepository + Send + Sync>,
    credential_schema_repository: Arc<dyn CredentialSchemaRepository + Send + Sync>,
    proof_schema_repository: Arc<dyn ProofSchemaRepository + Send + Sync>,
}

impl DataLayer {
    pub async fn create(database_url: &str) -> Self {
        let db = sea_orm::Database::connect(database_url)
            .await
            .expect("Database Connected");

        Migrator::up(&db, None).await.unwrap();

        let did_repository = Arc::new(DidProvider { db: db.clone() });
        let claim_schema_repository = Arc::new(ClaimSchemaProvider { db: db.clone() });
        let claim_repository = Arc::new(ClaimProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
        });
        let organisation_repository = Arc::new(OrganisationProvider { db: db.clone() });
        let credential_schema_repository = Arc::new(CredentialSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
        });
        let proof_schema_repository = Arc::new(ProofSchemaProvider {
            db: db.clone(),
            claim_schema_repository: claim_schema_repository.clone(),
            organisation_repository: organisation_repository.clone(),
            credential_schema_repository: credential_schema_repository.clone(),
        });
        Self {
            data_provider: Arc::new(OldProvider { db: db.clone() }),
            organisation_repository,
            credential_schema_repository,
            proof_schema_repository,
            claim_schema_repository,
            claim_repository,
            did_repository,
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
    fn get_did_repository(&self) -> Arc<dyn DidRepository + Send + Sync> {
        self.did_repository.clone()
    }
    fn get_claim_repository(&self) -> Arc<dyn ClaimRepository + Send + Sync> {
        self.claim_repository.clone()
    }
    fn get_claim_schema_repository(&self) -> Arc<dyn ClaimSchemaRepository + Send + Sync> {
        self.claim_schema_repository.clone()
    }
    fn get_credential_schema_repository(
        &self,
    ) -> Arc<dyn CredentialSchemaRepository + Send + Sync> {
        self.credential_schema_repository.clone()
    }
    fn get_proof_schema_repository(&self) -> Arc<dyn ProofSchemaRepository + Send + Sync> {
        self.proof_schema_repository.clone()
    }
}

pub(crate) struct OldProvider {
    pub db: DatabaseConnection,
}

#[async_trait::async_trait]
impl DataProvider for OldProvider {
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

    async fn create_credential(
        &self,
        request: CreateCredentialRequest,
        datatypes: &HashMap<String, DatatypeEntity>,
        exchanges: &HashMap<String, ExchangeEntity>,
    ) -> Result<EntityResponse, DataLayerError> {
        self.create_credential(request, datatypes, exchanges).await
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
