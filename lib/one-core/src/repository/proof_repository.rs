use super::error::DataLayerError;
use crate::model::proof::UpdateProofRequest;
use crate::model::{
    claim::Claim,
    did::Did,
    interaction::InteractionId,
    proof::{GetProofList, GetProofQuery, Proof, ProofId, ProofRelations, ProofState},
};

#[async_trait::async_trait]
pub trait ProofRepository {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError>;

    async fn get_proof(
        &self,
        id: &ProofId,
        relations: &ProofRelations,
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

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofState,
    ) -> Result<(), DataLayerError>;

    async fn set_proof_holder_did(
        &self,
        proof_id: &ProofId,
        holder_did: Did,
    ) -> Result<(), DataLayerError>;

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError>;

    async fn update_proof(&self, proof: UpdateProofRequest) -> Result<(), DataLayerError>;
}
