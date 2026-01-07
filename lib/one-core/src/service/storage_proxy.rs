use std::sync::Arc;

use anyhow::Context;
use futures::future::join_all;
use shared_types::{CredentialId, DidId, DidValue, InteractionId, KeyId, OrganisationId};

use crate::config::core_config::KeyAlgorithmType;
use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, CertificateRelations,
};
use crate::model::claim::ClaimRelations;
use crate::model::claim_schema::ClaimSchemaRelations;
use crate::model::credential::{
    Credential, CredentialFilterValue, CredentialRelations, CredentialRole, CredentialStateEnum,
    GetCredentialQuery,
};
use crate::model::credential_schema::{
    CredentialSchema, CredentialSchemaRelations, GetCredentialSchemaQuery,
};
use crate::model::did::Did;
use crate::model::identifier::{
    Identifier, IdentifierFilterValue, IdentifierListQuery, IdentifierRelations, IdentifierType,
};
use crate::model::interaction::{Interaction, InteractionRelations, UpdateInteractionRequest};
use crate::model::key::{Key, KeyFilterValue, KeyListQuery};
use crate::model::list_filter::{ListFilterCondition, ListFilterValue, StringMatch};
use crate::model::list_query::ListPagination;
use crate::model::organisation::OrganisationRelations;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::credential_repository::CredentialRepository;
use crate::repository::credential_schema_repository::CredentialSchemaRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::interaction_repository::InteractionRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::credential_schema::dto::{
    CredentialSchemaFilterValue, CredentialSchemaListIncludeEntityTypeEnum,
};

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

    async fn create_credential(&self, credential: Credential) -> anyhow::Result<CredentialId>;

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
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>>;

    /// Get holder credentials with a specified schema ID, usable for presentation.
    async fn get_presentation_credentials_by_schema_id(
        &self,
        schema_id: String,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Vec<Credential>>;

    async fn get_credential_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> anyhow::Result<Credential>;

    /// Get a credential schema from the storage layer matching any of the specified schema_ids.
    async fn find_schema_by_schema_ids(
        &self,
        schema_ids: &[String],
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>>;

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
}
pub(crate) type StorageAccess = dyn StorageProxy;

pub(crate) struct StorageProxyImpl {
    pub interactions: Arc<dyn InteractionRepository>,
    pub credential_schemas: Arc<dyn CredentialSchemaRepository>,
    pub credentials: Arc<dyn CredentialRepository>,
    pub dids: Arc<dyn DidRepository>,
    pub certificates: Arc<dyn CertificateRepository>,
    pub keys: Arc<dyn KeyRepository>,
    pub identifiers: Arc<dyn IdentifierRepository>,
}

impl StorageProxyImpl {
    pub(crate) fn new(
        interactions: Arc<dyn InteractionRepository>,
        credential_schemas: Arc<dyn CredentialSchemaRepository>,
        credentials: Arc<dyn CredentialRepository>,
        dids: Arc<dyn DidRepository>,
        certificates: Arc<dyn CertificateRepository>,
        keys: Arc<dyn KeyRepository>,
        identifiers: Arc<dyn IdentifierRepository>,
    ) -> Self {
        Self {
            interactions,
            credential_schemas,
            credentials,
            dids,
            certificates,
            keys,
            identifiers,
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
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>> {
        self.credential_schemas
            .get_by_schema_id_and_organisation(
                schema_id,
                organisation_id,
                &CredentialSchemaRelations {
                    claim_schemas: Some(Default::default()),
                    organisation: Some(Default::default()),
                },
            )
            .await
            .context("Error while fetching credential schema")
    }

    async fn find_schema_by_schema_ids(
        &self,
        schema_ids: &[String],
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Option<CredentialSchema>> {
        let schema_ids_filter_cond = schema_ids
            .iter()
            .map(|id| CredentialSchemaFilterValue::SchemaId(StringMatch::equals(id)))
            .fold(ListFilterCondition::default(), |acc, cond| acc | cond);
        let candidates = self
            .credential_schemas
            .get_credential_schema_list(
                GetCredentialSchemaQuery {
                    pagination: Some(ListPagination {
                        page: 0,
                        page_size: 1,
                    }),
                    sorting: None,
                    filtering: Some(
                        CredentialSchemaFilterValue::OrganisationId(organisation_id).condition()
                            & schema_ids_filter_cond,
                    ),
                    include: Some(vec![
                        CredentialSchemaListIncludeEntityTypeEnum::LayoutProperties,
                    ]),
                },
                &CredentialSchemaRelations {
                    claim_schemas: Some(ClaimSchemaRelations {}),
                    organisation: Some(OrganisationRelations::default()),
                },
            )
            .await
            .context("Error while fetching credential schema")?;
        Ok(candidates.values.into_iter().next())
    }

    async fn get_presentation_credentials_by_schema_id(
        &self,
        schema_id: String,
        organisation_id: OrganisationId,
    ) -> anyhow::Result<Vec<Credential>> {
        let credentials = self
            .credentials
            .get_credential_list(GetCredentialQuery {
                filtering: Some(
                    CredentialFilterValue::SchemaId(schema_id).condition()
                        & CredentialFilterValue::OrganisationId(organisation_id)
                        & CredentialFilterValue::States(vec![
                            CredentialStateEnum::Accepted,
                            CredentialStateEnum::Suspended,
                            CredentialStateEnum::Revoked,
                        ])
                        & CredentialFilterValue::Roles(vec![CredentialRole::Holder]),
                ),
                ..Default::default()
            })
            .await?
            .values;

        Ok(
            join_all(credentials.into_iter().map(|credential| async move {
                self.credentials
                    .get_credential(
                        &credential.id,
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
                            issuer_certificate: Some(CertificateRelations {
                                ..Default::default()
                            }),
                            ..Default::default()
                        },
                    )
                    .await
            }))
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect(),
        )
    }

    async fn get_credential_by_interaction_id(
        &self,
        interaction_id: &InteractionId,
    ) -> anyhow::Result<Credential> {
        Ok(self
            .credentials
            .get_credentials_by_interaction_id(
                interaction_id,
                &CredentialRelations {
                    holder_identifier: Some(IdentifierRelations {
                        ..Default::default()
                    }),
                    issuer_identifier: Some(IdentifierRelations {
                        did: Some(Default::default()),
                        certificates: Some(Default::default()),
                        ..Default::default()
                    }),
                    issuer_certificate: Some(Default::default()),
                    claims: Some(ClaimRelations {
                        schema: Some(Default::default()),
                    }),
                    schema: Some(CredentialSchemaRelations {
                        claim_schemas: Some(Default::default()),
                        organisation: Some(Default::default()),
                    }),
                    interaction: Some(InteractionRelations {
                        organisation: Some(Default::default()),
                    }),
                    ..Default::default()
                },
            )
            .await
            .context("Error while fetching credential by interaction id")?
            .into_iter()
            .next()
            .context("No credential by interaction id")?)
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

    async fn create_credential(&self, credential: Credential) -> anyhow::Result<CredentialId> {
        self.credentials
            .create_credential(credential)
            .await
            .context("Create credential error")
    }
}
