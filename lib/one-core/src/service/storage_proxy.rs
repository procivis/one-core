use std::sync::Arc;

use anyhow::Context;
use dto_mapper::{convert_inner, convert_inner_of_inner};
use one_providers::common_models::credential::OpenCredential;
use one_providers::common_models::credential_schema::{CredentialSchemaId, OpenCredentialSchema};
use one_providers::common_models::did::{DidId, DidValue, OpenDid};
use one_providers::common_models::interaction::{InteractionId, OpenInteraction};
use one_providers::common_models::organisation::OrganisationId;
use one_providers::exchange_protocol::openid4vc::StorageProxy;

use crate::model::claim::ClaimRelations;
use crate::model::credential::{to_open_credential, CredentialRelations};
use crate::model::credential_schema::{
    to_open_credential_schema, CredentialSchemaRelations, CredentialSchemaType,
};
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
    async fn create_interaction(
        &self,
        interaction: OpenInteraction,
    ) -> anyhow::Result<InteractionId> {
        convert_inner(
            self.interactions
                .create_interaction(interaction.into())
                .await
                .context("Create interaction error"),
        )
    }

    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<OpenCredentialSchema>> {
        let schema = self
            .credential_schemas
            .get_by_schema_id_and_organisation(
                schema_id,
                CredentialSchemaType::from(schema_type.to_string()),
                organisation_id.into(),
            )
            .await
            .context("Error while fetching credential schema")?;

        Ok(match schema {
            None => None,
            Some(schema) => Some(to_open_credential_schema(schema).await?),
        })
    }

    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
    ) -> anyhow::Result<Vec<OpenCredential>> {
        let credentials = self
            .credentials
            .get_credentials_by_credential_schema_id(
                schema_id.to_owned(),
                &CredentialRelations {
                    state: Some(Default::default()),
                    issuer_did: Some(Default::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {}),
                    ..Default::default()
                },
            )
            .await
            .context("Error while fetching credential by credential schema id")?;

        let mut result: Vec<OpenCredential> = vec![];
        for credential in credentials {
            result.push(to_open_credential(credential).await?);
        }
        Ok(result)
    }

    async fn create_credential_schema(
        &self,
        schema: OpenCredentialSchema,
    ) -> anyhow::Result<CredentialSchemaId> {
        let schema: crate::model::credential_schema::CredentialSchema = schema.into();

        convert_inner(
            self.credential_schemas
                .create_credential_schema(schema)
                .await
                .context("Create credential schema error"),
        )
    }

    async fn create_did(&self, did: OpenDid) -> anyhow::Result<DidId> {
        let did: crate::model::did::Did = did.into();

        convert_inner(
            self.dids
                .create_did(did)
                .await
                .context("Could not fetch did by value"),
        )
    }

    async fn get_did_by_value(&self, value: &DidValue) -> anyhow::Result<Option<OpenDid>> {
        convert_inner_of_inner(
            self.dids
                .get_did_by_value(&value.clone().into(), &Default::default())
                .await
                .context("Could not fetch did by value"),
        )
    }
}
