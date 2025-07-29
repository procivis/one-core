use std::sync::Arc;

use one_core::model::claim::{Claim, ClaimRelations};
use one_core::model::credential::{
    Credential, CredentialRelations, CredentialRole, CredentialStateEnum,
};
use one_core::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use one_core::model::identifier::{Identifier, IdentifierRelations};
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
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        organisation: Some(Default::default()),
                    }),
                    interaction: Some(Default::default()),
                    holder_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
                    key: Some(Default::default()),
                    issuer_identifier: Some(Default::default()),
                    issuer_certificate: Some(Default::default()),
                    ..Default::default()
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
        issuer_identifier: &Identifier,
        protocol: &str,
        params: TestingCredentialParams<'_>,
    ) -> Credential {
        let credential_id = Uuid::new_v4().into();
        let claim_schemas = credential_schema.claim_schemas.as_ref().unwrap();

        let claims = if let Some(claims_data) = params.claims_data {
            claims_data
                .into_iter()
                .map(|new_claim| {
                    let claim_schema = claim_schemas
                        .iter()
                        .find(|schema| schema.schema.id == new_claim.0)
                        .expect("Missing claim schema id");

                    Claim {
                        id: Uuid::new_v4(),
                        credential_id,
                        created_date: get_dummy_date(),
                        last_modified: get_dummy_date(),
                        value: new_claim.2.to_owned(),
                        path: new_claim.1.to_owned(),
                        schema: Some(claim_schema.schema.to_owned()),
                    }
                })
                .collect()
        } else {
            claim_schemas
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
                    } else if claim_schema.schema.data_type != "BOOLEAN" {
                        "test".to_string()
                    } else {
                        "true".to_string()
                    },
                    path: claim_schema.schema.key.clone(),
                    schema: Some(claim_schema.schema.to_owned()),
                })
                .collect()
        };

        let credential = Credential {
            id: credential_id,
            created_date: get_dummy_date(),
            last_modified: get_dummy_date(),
            issuance_date: get_dummy_date(),
            deleted_at: params.deleted_at,
            protocol: protocol.to_owned(),
            redirect_uri: None,
            role: params.role.unwrap_or(CredentialRole::Issuer),
            state,
            suspend_end_date: params.suspend_end_date,
            claims: Some(claims),
            issuer_identifier: Some(issuer_identifier.to_owned()),
            issuer_certificate: params.issuer_certificate.or(issuer_identifier
                .certificates
                .as_ref()
                .and_then(|certs| certs.first().cloned())),
            holder_identifier: params.holder_identifier,
            schema: Some(credential_schema.to_owned()),
            interaction: params.interaction,
            revocation_list: None,
            key: params.key,
            profile: params.profile,
            credential_blob_id: params.credential_blob_id,
        };

        let id = self
            .repository
            .create_credential(credential.to_owned())
            .await
            .unwrap();

        self.get(&id).await
    }
}
