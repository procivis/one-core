use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::ClaimSchemaRelations;
use one_core::model::credential_schema::CredentialSchemaRelations;
use one_core::model::did::{Did, DidRelations};
use one_core::model::interaction::Interaction;
use one_core::model::key::KeyRelations;
use one_core::model::proof::{
    Proof, ProofClaimRelations, ProofRelations, ProofState, ProofStateEnum, ProofStateRelations,
};
use one_core::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchema, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use one_core::repository::proof_repository::ProofRepository;
use one_providers::common_models::key::OpenKey;
use shared_types::ProofId;
use sql_data_provider::test_utilities::get_dummy_date;
use std::sync::Arc;
use uuid::Uuid;

pub struct ProofsDB {
    repository: Arc<dyn ProofRepository>,
}

impl ProofsDB {
    pub fn new(repository: Arc<dyn ProofRepository>) -> Self {
        Self { repository }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: Option<ProofId>,
        verifier_did: &Did,
        holder_did: Option<&Did>,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        exchange: &str,
        interaction: Option<&Interaction>,
        verifier_key: OpenKey,
    ) -> Proof {
        let proof = Proof {
            id: id.unwrap_or_else(|| Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date: get_dummy_date(),
            exchange: exchange.to_owned(),
            transport: "HTTP".to_string(),
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
            verifier_key: Some(verifier_key),
            interaction: interaction.cloned(),
        };

        let proof_id = self.repository.create_proof(proof.clone()).await.unwrap();

        self.get(&proof_id).await
    }

    pub async fn set_proof_claims(&self, id: &ProofId, claims: Vec<Claim>) {
        self.repository.set_proof_claims(id, claims).await.unwrap()
    }

    pub async fn get(&self, proof_id: &ProofId) -> Proof {
        self.repository
            .get_proof(
                proof_id,
                &ProofRelations {
                    state: Some(ProofStateRelations {}),
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        },
                        ..Default::default()
                    }),
                    schema: Some(ProofSchemaRelations {
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                    }),
                    holder_did: Some(DidRelations::default()),
                    verifier_did: Some(DidRelations::default()),
                    interaction: Some(Default::default()),
                    verifier_key: Some(KeyRelations::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
