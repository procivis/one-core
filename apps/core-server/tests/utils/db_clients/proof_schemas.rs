use std::sync::Arc;

use one_core::{
    model::{
        claim_schema::ClaimSchemaRelations,
        credential_schema::CredentialSchemaRelations,
        organisation::OrganisationRelations,
        proof_schema::{
            ProofSchema, ProofSchemaClaimRelations, ProofSchemaId, ProofSchemaRelations,
        },
    },
    repository::proof_schema_repository::ProofSchemaRepository,
};

pub struct ProofSchemasDB {
    repository: Arc<dyn ProofSchemaRepository>,
}

impl ProofSchemasDB {
    pub fn new(repository: Arc<dyn ProofSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, id: &ProofSchemaId) -> ProofSchema {
        self.repository
            .get_proof_schema(
                id,
                &ProofSchemaRelations {
                    claim_schemas: Some(ProofSchemaClaimRelations {
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(ClaimSchemaRelations {}),
                            ..Default::default()
                        }),
                    }),
                    organisation: Some(OrganisationRelations {}),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }
}
