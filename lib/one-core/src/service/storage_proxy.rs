use std::sync::Arc;

use anyhow::Context;
use shared_types::{CredentialSchemaId, DidValue, OrganisationId};

use crate::model::credential::{Credential, CredentialRelations};
use crate::model::credential_schema::{CredentialSchema, CredentialSchemaRelations};
use crate::model::did::{Did, DidRelations};
use crate::model::interaction::{Interaction, InteractionId};
use crate::provider::exchange_protocol::StorageProxy;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub struct StorageProxyImpl {
    pub organisation_id: OrganisationId,
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
}

impl StorageProxyImpl {
    pub fn new(
        organisation_id: OrganisationId,
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
    ) -> Self {
        Self {
            organisation_id,
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
        self.interactions
            .create_interaction(interaction)
            .await
            .context("Create interaction error")
    }

    async fn get_schema(
        &self,
        schema_id: &str,
        relations: &CredentialSchemaRelations,
    ) -> anyhow::Result<Option<CredentialSchema>> {
        self.credential_schemas
            .get_by_schema_id_and_organisation(schema_id, self.organisation_id, relations)
            .await
            .context("Error while fetching credential schema")
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
        relations: &CredentialRelations,
    ) -> anyhow::Result<Vec<Credential>> {
        self.credentials
            .get_credentials_by_credential_schema_id(schema_id.to_owned(), relations)
            .await
            .context("Error while fetching credential by credential schema id")
    }

    async fn create_credential_schema(
        &self,
        schema: CredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId> {
        self.credential_schemas
            .create_credential_schema(schema)
            .await
            .context("Create credential schema error")
    }

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        relations: &DidRelations,
    ) -> anyhow::Result<Option<Did>> {
        self.dids
            .get_did_by_value(value, relations)
            .await
            .context("get did by value error")
    }
}
