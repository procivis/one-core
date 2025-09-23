use std::sync::Arc;

use anyhow::Context;
use shared_types::{DidId, DidValue, KeyId, OrganisationId};

use crate::common_mapper::{IdentifierRole, RemoteIdentifierRelation, get_or_create_identifier};
use crate::config::core_config::KeyAlgorithmType;
use crate::model::certificate::{Certificate, CertificateFilterValue, CertificateListQuery};
use crate::model::claim::ClaimRelations;
use crate::model::credential::{Credential, CredentialRelations, CredentialRole};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, CredentialSchemaType,
};
use crate::model::did::Did;
use crate::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierRelations, IdentifierType,
};
use crate::model::interaction::{Interaction, InteractionId, UpdateInteractionRequest};
use crate::model::key::{Key, KeyFilterValue, KeyListQuery};
use crate::model::list_filter::ListFilterValue;
use crate::model::organisation::Organisation;
use crate::provider::credential_formatter::model::IdentifierDetails;
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::certificate::validator::CertificateValidator;

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
    async fn update_interaction(
        &self,
        id: InteractionId,
        request: UpdateInteractionRequest,
    ) -> anyhow::Result<()>;

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

    async fn get_certificate_by_fingerprint(
        &self,
        fingerprint: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Certificate>>;

    async fn get_key_by_raw_key_and_type(
        &self,
        raw_key: Vec<u8>,
        key_type: KeyAlgorithmType,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Key>>;

    async fn get_identifier_for_key(
        &self,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Identifier>>;

    async fn get_identifier_for_did(&self, did_id: &DidId) -> anyhow::Result<Identifier>;

    async fn get_or_create_identifier(
        &self,
        organisation: &Option<Organisation>,
        details: &IdentifierDetails,
        role: IdentifierRole,
    ) -> anyhow::Result<(Identifier, RemoteIdentifierRelation)>;
}
pub(crate) type StorageAccess = dyn StorageProxy;

pub(crate) struct StorageProxyImpl {
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
    pub certificates: Arc<dyn CertificateRepository>,
    pub certificate_validator: Arc<dyn CertificateValidator>,
    pub keys: Arc<dyn KeyRepository>,
    pub identifiers: Arc<dyn IdentifierRepository>,
    pub did_method_provider: Arc<dyn DidMethodProvider>,
    pub key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
}

impl StorageProxyImpl {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
        certificates: Arc<dyn CertificateRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        keys: Arc<dyn KeyRepository>,
        identifiers: Arc<dyn IdentifierRepository>,
        did_method_provider: Arc<dyn DidMethodProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    ) -> Self {
        Self {
            interactions,
            credential_schemas,
            credentials,
            dids,
            certificates,
            certificate_validator,
            keys,
            identifiers,
            did_method_provider,
            key_algorithm_provider,
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

    async fn update_interaction(
        &self,
        id: InteractionId,
        request: UpdateInteractionRequest,
    ) -> anyhow::Result<()> {
        self.interactions
            .update_interaction(id, request)
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

    async fn get_certificate_by_fingerprint(
        &self,
        fingerprint: &str,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Certificate>> {
        let list = self
            .certificates
            .list(CertificateListQuery {
                filtering: Some(
                    CertificateFilterValue::Fingerprint(fingerprint.to_owned()).condition()
                        & CertificateFilterValue::OrganisationId(organisation_id),
                ),
                ..Default::default()
            })
            .await?;
        Ok(list.values.into_iter().next())
    }

    async fn get_key_by_raw_key_and_type(
        &self,
        raw_key: Vec<u8>,
        key_type: KeyAlgorithmType,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Key>> {
        let keys = self
            .keys
            .get_key_list(KeyListQuery {
                filtering: Some(
                    KeyFilterValue::RawPublicKey(raw_key).condition()
                        & KeyFilterValue::KeyTypes(vec![key_type.to_string()])
                        & KeyFilterValue::OrganisationId(organisation_id),
                ),
                ..Default::default()
            })
            .await?;
        Ok(keys.values.into_iter().next())
    }

    async fn get_identifier_for_key(
        &self,
        key_id: KeyId,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<Identifier>> {
        let identifiers = self
            .identifiers
            .get_identifier_list(IdentifierListQuery {
                filtering: Some(
                    IdentifierFilterValue::KeyIds(vec![key_id]).condition()
                        & IdentifierFilterValue::Types(vec![IdentifierType::Key])
                        & IdentifierFilterValue::OrganisationId(organisation_id),
                ),
                ..Default::default()
            })
            .await?;
        Ok(identifiers.values.into_iter().next())
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

    async fn get_or_create_identifier(
        &self,
        organisation: &Option<Organisation>,
        details: &IdentifierDetails,
        role: IdentifierRole,
    ) -> anyhow::Result<(Identifier, RemoteIdentifierRelation)> {
        get_or_create_identifier(
            &*self.did_method_provider,
            &*self.dids,
            &*self.certificates,
            &*self.certificate_validator,
            &*self.keys,
            &*self.key_algorithm_provider,
            &*self.identifiers,
            organisation,
            details,
            role,
        )
        .await
        .context("get or create identifier")
    }
}
