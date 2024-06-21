use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialState, CredentialStateEnum,
};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::did::Did;
use one_core::repository::credential_repository::CredentialRepository;
use shared_types::CredentialId;
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
                    state: Some(Default::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        organisation: Some(Default::default()),
                    }),
                    holder_did: Some(Default::default()),
                    interaction: Some(Default::default()),
                    revocation_list: None,
                    issuer_did: None,
                    key: Some(Default::default()),
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
        exchange: &str,
        params: TestingCredentialParams<'_>,
    ) -> Credential {
        let credential_id = Uuid::new_v4().into();
        let claims = credential_schema
            .claim_schemas
            .as_ref()
            .unwrap()
            .iter()
            .filter(|claim_schema| {
                claim_schema.schema.data_type != "OBJECT" && !claim_schema.schema.array
            })
            .map(move |claim_schema| Claim {
                id: Uuid::new_v4(),
                credential_id,
                created_date: get_dummy_date(),
                last_modified: get_dummy_date(),
                value: if params.random_claims {
                    format!("test:{}", Uuid::new_v4())
                } else {
                    "test".to_string()
                },
                path: claim_schema.schema.key.clone(),
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
            exchange: exchange.to_owned(),
            redirect_uri: None,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            state: Some(vec![CredentialState {
                created_date: get_dummy_date(),
                state,
                suspend_end_date: params.suspend_end_date,
            }]),
            claims: Some(claims),
            issuer_did: Some(issuer_did.to_owned()),
            holder_did: params.holder_did,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            revocation_list: None,
            key: params.key,
        };

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }
}
