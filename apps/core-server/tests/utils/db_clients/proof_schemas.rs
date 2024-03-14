use std::sync::Arc;

use one_core::{
    model::{
        claim_schema::ClaimSchema,
        credential_schema::CredentialSchema,
        organisation::{Organisation, OrganisationRelations},
        proof_schema::{
            ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations, ProofSchema,
            ProofSchemaId, ProofSchemaRelations,
        },
    },
    repository::proof_schema_repository::ProofSchemaRepository,
};
use shared_types::ClaimSchemaId;
use sql_data_provider::test_utilities::get_dummy_date;
use time::OffsetDateTime;
use uuid::Uuid;

pub struct ProofSchemasDB {
    repository: Arc<dyn ProofSchemaRepository>,
}

pub struct CreateProofInputSchema<'a> {
    pub validity_constraint: Option<i64>,
    pub claims: Vec<CreateProofClaim<'a>>,
    pub credential_schema: &'a CredentialSchema,
}

pub struct CreateProofClaim<'a> {
    pub id: ClaimSchemaId,
    pub key: &'a str,
    pub required: bool,
    pub data_type: &'a str,
}

impl ProofSchemasDB {
    pub fn new(repository: Arc<dyn ProofSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        proof_input_schema: CreateProofInputSchema<'_>,
    ) -> ProofSchema {
        let claim_schemas = proof_input_schema
            .claims
            .iter()
            .enumerate()
            .map(|(order, claim)| ProofInputClaimSchema {
                schema: ClaimSchema {
                    id: claim.id,
                    key: claim.key.to_owned(),
                    data_type: claim.data_type.to_owned(),
                    created_date: get_dummy_date(),
                    last_modified: get_dummy_date(),
                },
                required: claim.required,
                order: order as _,
            })
            .collect();

        let input_schemas = vec![ProofInputSchema {
            validity_constraint: None,
            claim_schemas: Some(claim_schemas),
            credential_schema: Some(proof_input_schema.credential_schema.to_owned()),
        }];

        let proof_schema = ProofSchema {
            id: Uuid::new_v4(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            organisation: Some(organisation.to_owned()),
            deleted_at: None,
            claim_schemas: None,
            expire_duration: 0,
            validity_constraint: proof_input_schema.validity_constraint,
            input_schemas: Some(input_schemas),
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
                    claim_schemas: None,
                    organisation: Some(OrganisationRelations {}),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        credential_schema: Some(Default::default()),
                    }),
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn delete(&self, id: &ProofSchemaId) {
        let deleted_at = OffsetDateTime::now_utc();
        self.repository
            .delete_proof_schema(id, deleted_at)
            .await
            .unwrap();
    }
}

impl<'a> From<(&'a [(Uuid, &'a str, bool, &'a str)], &'a CredentialSchema)>
    for CreateProofInputSchema<'a>
{
    fn from(
        (claims, credential_schema): (&'a [(Uuid, &'a str, bool, &'a str)], &'a CredentialSchema),
    ) -> Self {
        Self {
            claims: claims.iter().map(Into::into).collect(),
            credential_schema,
            validity_constraint: None,
        }
    }
}

impl<'a> From<&'a (Uuid, &'a str, bool, &'a str)> for CreateProofClaim<'a> {
    fn from((id, key, required, data_type): &(Uuid, &'a str, bool, &'a str)) -> Self {
        Self {
            id: (*id).into(),
            key,
            required: *required,
            data_type,
        }
    }
}
