use shared_types::{InteractionId, ProofId};

use super::error::DataLayerError;
use crate::model::claim::Claim;
use crate::model::common::LockType;
use crate::model::history::HistoryErrorMetadata;
use crate::model::proof::{GetProofList, GetProofQuery, Proof, ProofRelations, UpdateProofRequest};

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub trait ProofRepository: Send + Sync {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError>;

    async fn get_proof(
        &self,
        id: &ProofId,
        relations: &ProofRelations,
        lock: Option<LockType>,
    ) -> Result<Option<Proof>, DataLayerError>;

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError>;

    async fn get_proof_list(
        &self,
        query_params: GetProofQuery,
    ) -> Result<GetProofList, DataLayerError>;

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError>;

    async fn delete_proof_claims(&self, proof_id: &ProofId) -> Result<(), DataLayerError>;

    async fn delete_proof(&self, proof_id: &ProofId) -> Result<(), DataLayerError>;

    async fn update_proof(
        &self,
        proof_id: &ProofId,
        proof: UpdateProofRequest,
        error_info: Option<HistoryErrorMetadata>,
    ) -> Result<(), DataLayerError>;
}
