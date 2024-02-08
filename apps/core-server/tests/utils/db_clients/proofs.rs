use std::sync::Arc;

use one_core::{
    model::{
        claim::{Claim, ClaimRelations},
        claim_schema::ClaimSchemaRelations,
        credential_schema::CredentialSchemaRelations,
        did::{Did, DidRelations},
        interaction::Interaction,
        organisation::OrganisationRelations,
        proof::{
            Proof, ProofClaimRelations, ProofId, ProofRelations, ProofState, ProofStateEnum,
            ProofStateRelations,
        },
        proof_schema::{ProofSchema, ProofSchemaClaimRelations, ProofSchemaRelations},
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

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: Option<Uuid>,
        verifier_did: &Did,
        holder_did: Option<&Did>,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        transport: &str,
        interaction: Option<&Interaction>,
    ) -> Proof {
        let proof = Proof {
            id: id.unwrap_or_else(Uuid::new_v4),
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
                        claim_schemas: Some(ProofSchemaClaimRelations {
                            credential_schema: Some(CredentialSchemaRelations {
                                claim_schemas: Some(ClaimSchemaRelations {}),
                                ..Default::default()
                            }),
                        }),
                        organisation: Some(OrganisationRelations {}),
                    }),
                    holder_did: Some(DidRelations::default()),
                    verifier_did: Some(DidRelations::default()),
                    interaction: Some(Default::default()),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
