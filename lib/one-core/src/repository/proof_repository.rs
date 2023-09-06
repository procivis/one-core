use super::error::DataLayerError;
use crate::model::{
    claim::Claim,
    did::Did,
    proof::{GetProofList, GetProofQuery, Proof, ProofId, ProofRelations, ProofState},
};

#[async_trait::async_trait]
pub trait ProofRepository {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError>;

    async fn get_proof(
        &self,
        id: &ProofId,
        relations: &ProofRelations,
    ) -> Result<Proof, DataLayerError>;

    async fn get_proof_list(
        &self,
        query_params: GetProofQuery,
    ) -> Result<GetProofList, DataLayerError>;

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofState,
    ) -> Result<(), DataLayerError>;

    async fn set_proof_receiver_did(
        &self,
        proof_id: &ProofId,
        receiver_did: Did,
    ) -> Result<(), DataLayerError>;

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError>;
}
