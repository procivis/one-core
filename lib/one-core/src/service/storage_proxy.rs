use std::sync::Arc;

use anyhow::Context;
use shared_types::OrganisationId;

use crate::{
    model::{
        credential_schema::{CredentialSchema, CredentialSchemaRelations},
        interaction::{Interaction, InteractionId},
    },
    provider::exchange_protocol::StorageProxy,
    repository::{
        credential_schema_repository::CredentialSchemaRepository,
        interaction_repository::InteractionRepository,
    },
};

pub struct StorageProxyImpl {
    pub organisation_id: OrganisationId,
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
}

impl StorageProxyImpl {
    pub fn new(
        organisation_id: OrganisationId,
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
    ) -> Self {
        Self {
            organisation_id,
            interactions,
            credential_schemas,
        }
    }
}

#[async_trait::async_trait]
impl StorageProxy for StorageProxyImpl {
    async fn create_interaction(
        &self,
        interaction: Interaction,
    ) -> Result<InteractionId, anyhow::Error> {
        self.interactions
            .create_interaction(interaction)
            .await
            .context("Create interaction error")
    }
    async fn get_schema(
        &self,
        schema_id: &str,
        relations: &CredentialSchemaRelations,
    ) -> Result<Option<CredentialSchema>, anyhow::Error> {
        self.credential_schemas
            .get_by_schema_id_and_organisation(schema_id, self.organisation_id, relations)
            .await
            .context("Error while fetching credential schema")
    }
    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> Result<shared_types::CredentialSchemaId, anyhow::Error> {
        self.credential_schemas
            .create_credential_schema(schema)
            .await
            .context("Create credential schema error")
    }
}
