use std::sync::Arc;

use anyhow::Context;
use shared_types::{DidId, DidValue, OrganisationId};

use crate::common_mapper::{DidRole, get_or_create_did_and_identifier};
use crate::model::claim::ClaimRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialRole};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType,
};
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierRelations};
use crate::model::interaction::{Interaction, InteractionId, UpdateInteractionRequest};
use crate::model::organisation::Organisation;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;

/// Interface to be implemented in order to use an exchange protocol.
///
/// The exchange protocol provider relies on storage of data for interactions,
/// credentials, credential schemas, and DIDs. A storage layer must be
/// chosen and implemented for the exchange protocol to be enabled.
#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait StorageProxy: Send + Sync {
    /// Store an interaction with a chosen storage layer.
    async fn create_interaction(&self, interaction: Interaction) -> anyhow::Result<InteractionId>;

    /// Store an interaction with a chosen storage layer.
    async fn update_interaction(&self, request: UpdateInteractionRequest) -> anyhow::Result<()>;

    /// Get a credential schema from a chosen storage layer.
    async fn get_schema(
        &self,
        schema_id: &str,
        schema_type: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>>;

    /// Get credentials from a specified schema ID, from a chosen storage layer.
    async fn get_credentials_by_credential_schema_id(
        &self,
        schema_id: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Vec<Credential>>;

    /// Obtain a DID by its address, from a chosen storage layer.
    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Did>>;

    async fn get_identifier_for_did(&self, did_id: &DidId) -> anyhow::Result<Identifier>;

    async fn get_or_create_did_and_identifier(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        did_role: DidRole,
    ) -> anyhow::Result<(Did, Identifier)>;
}
pub(crate) type StorageAccess = dyn StorageProxy;

pub(crate) struct StorageProxyImpl {
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
    pub identifiers: Arc<dyn IdentifierRepository>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
}

impl StorageProxyImpl {
    pub(crate) fn new(
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
        identifiers: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
    ) -> Self {
        Self {
            interactions,
            credential_schemas,
            credentials,
            dids,
            identifiers,
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

    async fn update_interaction(&self, request: UpdateInteractionRequest) -> anyhow::Result<()> {
        self.interactions
            .update_interaction(request)
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
                    holder_identifier: Some(IdentifierRelations {
                        ..Default::default()
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        ..Default::default()
                    }),
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
            .filter(|cred| cred.role == CredentialRole::Holder)
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

    async fn get_did_by_value(
        &self,
        value: &DidValue,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Did>> {
        self.dids
            .get_did_by_value(value, Some(Some(organisation_id)), &Default::default())
            .await
            .context("Could not fetch did by value")
    }

    async fn get_identifier_for_did(&self, did_id: &DidId) -> anyhow::Result<Identifier> {
        self.identifiers
            .get_from_did_id(*did_id, &Default::default())
            .await
            .context("Could not fetch identifier by didId")
            .and_then(|identifier| {
                identifier.ok_or(anyhow::anyhow!("Could not find identifier by didId"))
            })
    }

    async fn get_or_create_did_and_identifier(
        &self,
        organisation: &Option<Organisation>,
        did_value: &DidValue,
        did_role: DidRole,
    ) -> anyhow::Result<(Did, Identifier)> {
        get_or_create_did_and_identifier(
            &*self.did_method_provider,
            &*self.dids,
            &*self.identifiers,
            organisation,
            did_value,
            did_role,
        )
        .await
        .context("get or create did and identifier")
    }
}
