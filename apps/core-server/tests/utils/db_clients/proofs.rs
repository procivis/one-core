use std::sync::Arc;

use one_core::{
    model::{
        claim::Claim,
        did::Did,
        interaction::Interaction,
        proof::{Proof, ProofId, ProofState, ProofStateEnum},
        proof_schema::ProofSchema,
    },
    repository::proof_repository::ProofRepository,
};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct ProofsDB {
    repository: Arc<dyn ProofRepository>,
}

impl ProofsDB {
    pub fn new(repository: Arc<dyn ProofRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        verifier_did: &Did,
        holder_did: Option<&Did>,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        transport: &str,
        interaction: Option<&Interaction>,
    ) -> Proof {
        let proof = Proof {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date: get_dummy_date(),
            transport: transport.to_owned(),
            redirect_uri: None,
            state: Some(vec![ProofState {
                state,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
            }]),
            claims: None,
            schema: proof_schema.cloned(),
            verifier_did: Some(verifier_did.to_owned()),
            holder_did: holder_did.cloned(),
            interaction: interaction.cloned(),
        };

        self.repository.create_proof(proof.clone()).await.unwrap();

        proof
    }

    pub async fn set_proof_claims(&self, id: &ProofId, claims: Vec<Claim>) {
        self.repository.set_proof_claims(id, claims).await.unwrap()
    }
}
