use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::ClaimSchemaRelations;
use one_core::model::credential_schema::CredentialSchemaRelations;
use one_core::model::identifier::{Identifier, IdentifierRelations};
use one_core::model::interaction::Interaction;
use one_core::model::key::{Key, KeyRelations};
use one_core::model::organisation::OrganisationRelations;
use one_core::model::proof::{
    Proof, ProofClaim, ProofClaimRelations, ProofRelations, ProofRole, ProofStateEnum,
};
use one_core::model::proof_schema::{
    ProofInputSchemaRelations, ProofSchema, ProofSchemaClaimRelations, ProofSchemaRelations,
};
use one_core::repository::proof_repository::ProofRepository;
use shared_types::{BlobId, ProofId};
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
        id: Option<ProofId>,
        verifier_identifier: &Identifier,
        holder_identifier: Option<&Identifier>,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        exchange: &str,
        interaction: Option<&Interaction>,
        verifier_key: Key,
        proof_blob_id: Option<BlobId>,
    ) -> Proof {
        self.create_with_profile(
            id,
            verifier_identifier,
            holder_identifier,
            proof_schema,
            state,
            exchange,
            interaction,
            verifier_key,
            None,
            proof_blob_id,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_with_profile(
        &self,
        id: Option<ProofId>,
        verifier_identifier: &Identifier,
        holder_identifier: Option<&Identifier>,
        proof_schema: Option<&ProofSchema>,
        state: ProofStateEnum,
        exchange: &str,
        interaction: Option<&Interaction>,
        verifier_key: Key,
        profile: Option<String>,
        proof_blob_id: Option<BlobId>,
    ) -> Proof {
        let requested_date = match state {
            ProofStateEnum::Pending
            | ProofStateEnum::Requested
            | ProofStateEnum::Accepted
            | ProofStateEnum::Rejected
            | ProofStateEnum::Error => Some(get_dummy_date()),
            _ => None,
        };

        let completed_date = match state {
            ProofStateEnum::Accepted | ProofStateEnum::Rejected => Some(get_dummy_date()),
            _ => None,
        };

        let role = if proof_schema.is_some() {
            ProofRole::Verifier
        } else {
            ProofRole::Holder
        };

        let proof = Proof {
            id: id.unwrap_or_else(|| Uuid::new_v4().into()),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            protocol: exchange.to_owned(),
            transport: "HTTP".to_string(),
            redirect_uri: None,
            state,
            role,
            requested_date,
            completed_date,
            claims: Some(vec![ProofClaim {
                claim: Claim {
                    id: Default::default(),
                    credential_id: Uuid::default().into(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                    value: Some("test".to_string()),
                    path: "test".to_string(),
                    schema: None,
                },
                credential: None,
            }]),
            schema: proof_schema.cloned(),
            verifier_identifier: Some(verifier_identifier.to_owned()),
            holder_identifier: holder_identifier.cloned(),
            verifier_key: Some(verifier_key),
            verifier_certificate: verifier_identifier
                .certificates
                .iter()
                .flat_map(|v| v.first())
                .next()
                .cloned(),
            interaction: interaction.cloned(),
            profile,
            proof_blob_id,
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
                    claims: Some(ProofClaimRelations {
                        claim: ClaimRelations {
                            schema: Some(ClaimSchemaRelations::default()),
                        },
                        ..Default::default()
                    }),
                    schema: Some(ProofSchemaRelations {
                        organisation: Some(OrganisationRelations {}),
                        proof_inputs: Some(ProofInputSchemaRelations {
                            claim_schemas: Some(ProofSchemaClaimRelations::default()),
                            credential_schema: Some(CredentialSchemaRelations::default()),
                        }),
                    }),
                    verifier_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    interaction: Some(Default::default()),
                    verifier_key: Some(KeyRelations::default()),
                    ..Default::default()
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
