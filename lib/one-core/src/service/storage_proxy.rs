use std::sync::Arc;

use anyhow::Context;
use dto_mapper::{convert_inner, convert_inner_of_inner};
use one_providers::common_models::credential::Credential;
use one_providers::common_models::credential_schema::{CredentialSchema, CredentialSchemaId};
use one_providers::common_models::did::{Did, DidId, DidValue};
use one_providers::common_models::interaction::{Interaction, InteractionId};
use one_providers::exchange_protocol::openid4vc::StorageProxy;

use crate::model::claim::ClaimRelations;
use crate::model::credential::CredentialRelations;
use crate::model::credential_schema::CredentialSchemaRelations;
use crate::model::organisation::Organisation;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub struct StorageProxyImpl {
    pub organisation: Organisation,
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
}

impl StorageProxyImpl {
    pub fn new(
        organisation: Organisation,
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
    ) -> Self {
        Self {
            organisation,
            interactions,
            credential_schemas,
            credentials,
            dids,
        }
    }
}

#[async_trait::async_trait]
impl StorageProxy for StorageProxyImpl {
    async fn create_interaction(&self, interaction: Interaction) -> anyhow::Result<InteractionId> {
        convert_inner(
            self.interactions
                .create_interaction(interaction.into())
                .await
                .context("Create interaction error"),
        )
    }

    async fn get_schema(&self, schema_id: &str) -> anyhow::Result<Option<CredentialSchema>> {
        convert_inner_of_inner(
            self.credential_schemas
                .get_by_schema_id_and_organisation(
                    schema_id,
                    self.organisation.id,
                    &CredentialSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        organisation: Some(Default::default()),
                    },
                )
                .await
                .context("Error while fetching credential schema"),
        )
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
    ) -> anyhow::Result<Vec<Credential>> {
        convert_inner_of_inner(
            self.credentials
                .get_credentials_by_credential_schema_id(
                    schema_id.to_owned(),
                    &CredentialRelations {
                        state: Some(Default::default()),
                        issuer_did: Some(Default::default()),
                        claims: Some(ClaimRelations {
                            schema: Some(Default::default()),
                        }),
                        schema: Some(CredentialSchemaRelations {
                            claim_schemas: Some(Default::default()),
                            organisation: Some(Default::default()),
                        }),
                        ..Default::default()
                    },
                )
                .await
                .context("Error while fetching credential by credential schema id"),
        )
    }

    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId> {
        let mut schema: crate::model::credential_schema::CredentialSchema = schema.into();
        schema.organisation = Some(self.organisation.to_owned());

        convert_inner(
            self.credential_schemas
                .create_credential_schema(schema)
                .await
                .context("Create credential schema error"),
        )
    }

    async fn create_did(&self, did: Did) -> anyhow::Result<DidId> {
        let mut did: crate::model::did::Did = did.into();
        did.organisation = Some(self.organisation.to_owned());

        convert_inner(
            self.dids
                .create_did(did)
                .await
                .context("Could not fetch did by value"),
        )
    }

    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<Did>> {
        convert_inner_of_inner(
            self.dids
                .get_did_by_value(&value.clone().into(), &Default::default())
                .await
                .context("Could not fetch did by value"),
        )
    }
}
