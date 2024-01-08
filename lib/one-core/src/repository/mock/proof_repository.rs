use crate::model::proof::UpdateProofRequest;
use crate::{
    model::{
        claim::Claim,
        did::Did,
        interaction::InteractionId,
        proof::{GetProofList, GetProofQuery, Proof, ProofId, ProofRelations, ProofState},
    },
    repository::error::DataLayerError,
};
use mockall::*;

#[derive(Default)]
struct ProofRepository;

mock! {
    pub ProofRepository {
        pub fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError>;

        pub fn get_proof(
            &self,
            id: &ProofId,
            relations: &ProofRelations,
        ) -> Result<Option<Proof>, DataLayerError>;

        pub fn get_proof_by_interaction_id(
            &self,
            interaction_id: &InteractionId,
            relations: &ProofRelations,
        ) -> Result<Option<Proof>, DataLayerError>;

        pub fn get_proof_list(
            &self,
            query_params: GetProofQuery,
        ) -> Result<GetProofList, DataLayerError>;

        pub fn update_proof(&self, proof: UpdateProofRequest) -> Result<(), DataLayerError>;

        pub fn set_proof_state(
            &self,
            proof_id: &ProofId,
            state: ProofState,
        ) -> Result<(), DataLayerError>;

        pub fn set_proof_holder_did(
            &self,
            proof_id: &ProofId,
            holder_did: Did,
        ) -> Result<(), DataLayerError>;

        pub fn set_proof_claims(
            &self,
            proof_id: &ProofId,
            claims: Vec<Claim>,
        ) -> Result<(), DataLayerError>;
    }
}

#[async_trait::async_trait]
impl crate::repository::proof_repository::ProofRepository for MockProofRepository {
    async fn create_proof(&self, request: Proof) -> Result<ProofId, DataLayerError> {
        self.create_proof(request)
    }

    async fn get_proof(
        &self,
        id: &ProofId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        self.get_proof(id, relations)
    }

    async fn get_proof_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
        relations: &ProofRelations,
    ) -> Result<Option<Proof>, DataLayerError> {
        self.get_proof_by_interaction_id(interaction_id, relations)
    }

    async fn get_proof_list(
        &self,
        query_params: GetProofQuery,
    ) -> Result<GetProofList, DataLayerError> {
        self.get_proof_list(query_params)
    }

    async fn set_proof_state(
        &self,
        proof_id: &ProofId,
        state: ProofState,
    ) -> Result<(), DataLayerError> {
        self.set_proof_state(proof_id, state)
    }

    async fn set_proof_holder_did(
        &self,
        proof_id: &ProofId,
        holder_did: Did,
    ) -> Result<(), DataLayerError> {
        self.set_proof_holder_did(proof_id, holder_did)
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        self.set_proof_claims(proof_id, claims)
    }

    async fn update_proof(&self, proof: UpdateProofRequest) -> Result<(), DataLayerError> {
        self.update_proof(proof)
    }
}
