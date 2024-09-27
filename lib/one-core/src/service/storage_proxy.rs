use std::sync::Arc;

use anyhow::Context;
use one_dto_mapper::{convert_inner, convert_inner_of_inner};
use shared_types::{CredentialSchemaId, DidId, DidValue, OrganisationId};

use crate::model::claim::ClaimRelations;
use crate::model::credential::{Credential, CredentialRelations};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType,
};
use crate::model::did::Did;
use crate::model::interaction::{Interaction, InteractionId};
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
}

impl StorageProxyImpl {
    pub fn new(
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
    ) -> Self {
        Self {
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
                .create_interaction(interaction)
                .await
                .context("Create interaction error"),
        )
    }

    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>> {
        convert_inner_of_inner(
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
        convert_inner(
            self.credential_schemas
                .create_credential_schema(schema)
                .await
                .context("Create credential schema error"),
        )
    }

    async fn create_did(&self, did: Did) -> anyhow::Result<DidId> {
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
                .get_did_by_value(value, &Default::default())
                .await
                .context("Could not fetch did by value"),
        )
    }
}
