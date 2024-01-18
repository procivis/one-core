use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::claim_schema::ClaimSchemaRelations;
use one_core::model::credential::{
    Credential, CredentialId, CredentialRelations, CredentialRole, CredentialState,
    CredentialStateEnum, CredentialStateRelations,
};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::did::{Did, DidRelations};
use one_core::model::interaction::InteractionRelations;
use one_core::model::organisation::OrganisationRelations;
use one_core::repository::credential_repository::CredentialRepository;
use sql_data_provider::test_utilities::get_dummy_date;
use uuid::Uuid;

use crate::fixtures::TestingCredentialParams;

pub struct CredentialsDB {
    repository: Arc<dyn CredentialRepository>,
}

impl CredentialsDB {
    pub fn new(repository: Arc<dyn CredentialRepository>) -> Self {
        Self { repository }
    }

    pub async fn get(&self, credential_id: &CredentialId) -> Credential {
        self.repository
            .get_credential(
                credential_id,
                &CredentialRelations {
                    state: Some(CredentialStateRelations {}),
                    claims: Some(ClaimRelations {
                        schema: Some(ClaimSchemaRelations {}),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(ClaimSchemaRelations {}),
                        organisation: Some(OrganisationRelations {}),
                    }),
                    holder_did: Some(DidRelations::default()),
                    interaction: Some(InteractionRelations {}),
                    revocation_list: None,
                    issuer_did: None,
                    key: None,
                },
            )
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn create(
        &self,
        credential_schema: &CredentialSchema,
        state: CredentialStateEnum,
        issuer_did: &Did,
        transport: &str,
        params: TestingCredentialParams<'_>,
    ) -> Credential {
        let credential_id = Uuid::new_v4();
        let claims = credential_schema
            .claim_schemas
            .as_ref()
            .unwrap()
            .iter()
            .map(move |claim_schema| Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                value: "test".to_string(),
                schema: Some(claim_schema.schema.to_owned()),
            })
            .collect();

        let credential = Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date: get_dummy_date(),
            deleted_at: params.deleted_at,
            credential: params.credential.unwrap_or("").as_bytes().to_owned(),
            transport: transport.to_owned(),
            redirect_uri: None,
            role: CredentialRole::Issuer,
            state: Some(vec![CredentialState {
                created_date: get_dummy_date(),
                state,
            }]),
            claims: Some(claims),
            issuer_did: Some(issuer_did.to_owned()),
            holder_did: params.holder_did,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            revocation_list: None,
            key: None,
        };

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }
}
