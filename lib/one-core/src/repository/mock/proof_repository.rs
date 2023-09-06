use crate::{
    model::{
        claim::Claim,
        did::Did,
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
        ) -> Result<Proof, DataLayerError>;

        pub fn get_proof_list(
            &self,
            query_params: GetProofQuery,
        ) -> Result<GetProofList, DataLayerError>;

        pub fn set_proof_state(
            &self,
            proof_id: &ProofId,
            state: ProofState,
        ) -> Result<(), DataLayerError>;

        pub fn set_proof_receiver_did(
            &self,
            proof_id: &ProofId,
            receiver_did: Did,
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
    ) -> Result<Proof, DataLayerError> {
        self.get_proof(id, relations)
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

    async fn set_proof_receiver_did(
        &self,
        proof_id: &ProofId,
        receiver_did: Did,
    ) -> Result<(), DataLayerError> {
        self.set_proof_receiver_did(proof_id, receiver_did)
    }

    async fn set_proof_claims(
        &self,
        proof_id: &ProofId,
        claims: Vec<Claim>,
    ) -> Result<(), DataLayerError> {
        self.set_proof_claims(proof_id, claims)
    }
}
