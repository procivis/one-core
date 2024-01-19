use std::sync::Arc;

use one_core::{
    model::{
        claim_schema::{ClaimSchema, ClaimSchemaRelations},
        credential_schema::CredentialSchemaRelations,
        organisation::{Organisation, OrganisationRelations},
        proof_schema::{
            ProofSchema, ProofSchemaClaim, ProofSchemaClaimRelations, ProofSchemaId,
            ProofSchemaRelations,
        },
    },
    repository::proof_schema_repository::ProofSchemaRepository,
};
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

pub struct ProofSchemasDB {
    repository: Arc<dyn ProofSchemaRepository>,
}

impl ProofSchemasDB {
    pub fn new(repository: Arc<dyn ProofSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        claims: &[(Uuid, &str, bool, &str)],
    ) -> ProofSchema {
        let claim_schemas = claims
            .iter()
            .map(|(id, key, required, data_type)| ProofSchemaClaim {
                schema: ClaimSchema {
                    id: id.to_owned(),
                    key: key.to_string(),
                    data_type: data_type.to_string(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: required.to_owned(),
                credential_schema: None,
            })
            .collect();

        let proof_schema = ProofSchema {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            organisation: Some(organisation.to_owned()),
            deleted_at: None,
            claim_schemas: Some(claim_schemas),
            expire_duration: 0,
        };

        let id = self
            .repository
            .create_proof_schema(proof_schema.to_owned())
            .await
            .unwrap();

        self.get(&id).await
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
