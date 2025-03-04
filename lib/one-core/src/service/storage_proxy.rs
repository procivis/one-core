use std::sync::Arc;

use anyhow::Context;
use shared_types::{CredentialSchemaId, DidId, DidValue, OrganisationId};

use crate::common_mapper::{get_or_create_did, DidRole};
use crate::model::claim::ClaimRelations;
use crate::model::credential::{Credential, CredentialRelations};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType,
};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
use crate::model::organisation::Organisation;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::exchange_protocol::StorageProxy;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::interaction_repository::InteractionRepository;

pub struct StorageProxyImpl {
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
}

impl StorageProxyImpl {
    pub fn new(
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            interactions,
            credential_schemas,
            credentials,
            dids,
            did_method_provider,
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

    async fn update_interaction(&self, interaction: Interaction) -> anyhow::Result<()> {
        self.interactions
            .update_interaction(interaction)
            .await
            .context("failed to update interaction")
    }

    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>> {
        self.credential_schemas
            .get_by_schema_id_and_organisation(
                schema_id,
                CredentialSchemaType::from(schema_type.to_string()),
                organisation_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await
            .context("Error while fetching credential schema")
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Vec<Credential>> {
        Ok(self
            .credentials
            .get_credentials_by_credential_schema_id(
                schema_id.to_owned(),
                &CredentialRelations {
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
            .context("Error while fetching credential by credential schema id")?
            .into_iter()
            .filter(|cred| cred.deleted_at.is_none())
            .filter(|cred| {
                cred.schema.as_ref().is_some_and(|schema| {
                    schema
                        .organisation
                        .as_ref()
                        .is_some_and(|o| o.id == organisation_id)
                })
            })
            .collect::<Vec<_>>())
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

    async fn create_did(&self, did: Did) -> anyhow::Result<DidId> {
        self.dids
            .create_did(did)
            .await
            .context("Could not create did")
    }

    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<Did>> {
        self.dids
            .get_did_by_value(value, &Default::default())
            .await
            .context("Could not fetch did by value")
    }

    async fn get_or_create_did(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        did_role: DidRole,
    ) -> anyhow::Result<Did> {
        get_or_create_did(
            &*self.did_method_provider,
            &*self.dids,
            organisation,
            did_value,
            did_role,
        )
        .await
        .context("get or create did")
    }
}
