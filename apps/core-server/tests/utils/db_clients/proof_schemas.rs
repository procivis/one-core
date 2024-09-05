use std::sync::Arc;

use one_core::model::claim_schema::ClaimSchema;
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::organisation::{Organisation, OrganisationRelations};
use one_core::model::proof_schema::{
    ProofInputClaimSchema, ProofInputSchema, ProofInputSchemaRelations, ProofSchema,
    ProofSchemaRelations,
};
use one_core::repository::proof_schema_repository::ProofSchemaRepository;
use shared_types::{ClaimSchemaId, ProofSchemaId};
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
    pub array: bool,
}

impl ProofSchemasDB {
    pub fn new(repository: Arc<dyn ProofSchemaRepository>) -> Self {
        Self { repository }
    }

    pub async fn create(
        &self,
        name: &str,
        organisation: &Organisation,
        proof_input_schemas: Vec<CreateProofInputSchema<'_>>,
    ) -> ProofSchema {
        let mut input_schemas: Vec<ProofInputSchema> = vec![];
        for proof_input_schema in proof_input_schemas {
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
                        array: claim.array,
                    },
                    required: claim.required,
                    order: order as _,
                })
                .collect();

            input_schemas.push(ProofInputSchema {
                validity_constraint: proof_input_schema.validity_constraint,
                claim_schemas: Some(claim_schemas),
                credential_schema: Some(proof_input_schema.credential_schema.to_owned()),
            });
        }

        let proof_schema = ProofSchema {
            id: Uuid::new_v4().into(),
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            name: name.to_owned(),
            organisation: Some(organisation.to_owned()),
            deleted_at: None,
            expire_duration: 10,
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
                    organisation: Some(OrganisationRelations {}),
                    proof_inputs: Some(ProofInputSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        credential_schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(Default::default()),
                            ..Default::default()
                        }),
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

impl<'a>
    From<(
        &'a [(Uuid, &'a str, bool, &'a str, bool)],
        &'a CredentialSchema,
    )> for CreateProofInputSchema<'a>
{
    fn from(
        (claims, credential_schema): (
            &'a [(Uuid, &'a str, bool, &'a str, bool)],
            &'a CredentialSchema,
        ),
    ) -> Self {
        Self {
            claims: claims.iter().map(Into::into).collect(),
            credential_schema,
            validity_constraint: None,
        }
    }
}

impl<'a> From<&'a (Uuid, &'a str, bool, &'a str, bool)> for CreateProofClaim<'a> {
    fn from((id, key, required, data_type, array): &(Uuid, &'a str, bool, &'a str, bool)) -> Self {
        Self {
            id: (*id).into(),
            key,
            required: *required,
            data_type,
            array: *array,
        }
    }
}
