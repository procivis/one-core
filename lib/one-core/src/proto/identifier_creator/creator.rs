use std::sync::Arc;

use futures::FutureExt;

use super::{
    CreateLocalIdentifierRequest, IdentifierCreator, IdentifierRole, RemoteIdentifierRelation,
};
use crate::config::core_config::CoreConfig;
use crate::model::identifier::Identifier;
use crate::model::organisation::Organisation;
use crate::proto::csr_creator::CsrCreator;
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::signer::provider::SignerProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::service::error::ServiceError;
use crate::{CertificateValidator, KeyAlgorithmProvider};

pub(crate) struct IdentifierCreatorProto {
    pub(super) did_method_provider: Arc<dyn DidMethodProvider>,
    pub(super) did_repository: Arc<dyn DidRepository>,
    pub(super) certificate_repository: Arc<dyn CertificateRepository>,
    pub(super) certificate_validator: Arc<dyn CertificateValidator>,
    pub(super) key_repository: Arc<dyn KeyRepository>,
    pub(super) key_provider: Arc<dyn KeyProvider>,
    pub(super) key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
    pub(super) identifier_repository: Arc<dyn IdentifierRepository>,
    pub(super) csr_creator: Arc<dyn CsrCreator>,
    pub(super) signer_provider: Arc<dyn SignerProvider>,
    pub(super) config: Arc<CoreConfig>,
    tx_manager: Arc<dyn TransactionManager>,
}

impl IdentifierCreatorProto {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        did_method_provider: Arc<dyn DidMethodProvider>,
        did_repository: Arc<dyn DidRepository>,
        certificate_repository: Arc<dyn CertificateRepository>,
        certificate_validator: Arc<dyn CertificateValidator>,
        key_repository: Arc<dyn KeyRepository>,
        key_provider: Arc<dyn KeyProvider>,
        key_algorithm_provider: Arc<dyn KeyAlgorithmProvider>,
        identifier_repository: Arc<dyn IdentifierRepository>,
        csr_creator: Arc<dyn CsrCreator>,
        signer_provider: Arc<dyn SignerProvider>,
        config: Arc<CoreConfig>,
        tx_manager: Arc<dyn TransactionManager>,
    ) -> Self {
        Self {
            did_method_provider,
            did_repository,
            certificate_repository,
            certificate_validator,
            key_repository,
            key_provider,
            key_algorithm_provider,
            identifier_repository,
            csr_creator,
            signer_provider,
            config,
            tx_manager,
        }
    }
}

#[async_trait::async_trait]
impl IdentifierCreator for IdentifierCreatorProto {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn get_or_create_remote_identifier(
        &self,
        organisation: &Option<Organisation>,
        details: &IdentifierDetails,
        role: IdentifierRole,
    ) -> Result<(Identifier, RemoteIdentifierRelation), ServiceError> {
        let result = self
            .tx_manager
            .tx_with_config(
                async {
                    Ok::<_, ServiceError>(match details {
                        IdentifierDetails::Did(did_value) => {
                            let (did, identifier) = self
                                .get_or_create_did_and_identifier(organisation, did_value, role)
                                .await?;
                            (identifier, RemoteIdentifierRelation::Did(did))
                        }
                        IdentifierDetails::Certificate(CertificateDetails {
                            chain,
                            fingerprint,
                            ..
                        }) => {
                            let (certificate, identifier) = self
                                .get_or_create_certificate_identifier(
                                    organisation,
                                    chain.to_owned(),
                                    fingerprint.to_owned(),
                                    role,
                                )
                                .await?;

                            (
                                identifier,
                                RemoteIdentifierRelation::Certificate(certificate),
                            )
                        }
                        IdentifierDetails::Key(public_key_jwk) => {
                            let (key, identifier) = self
                                .get_or_create_key_identifier(
                                    organisation.as_ref(),
                                    public_key_jwk,
                                    role,
                                )
                                .await?;
                            (identifier, RemoteIdentifierRelation::Key(key))
                        }
                    })
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await?;

        match result {
            Err(ServiceError::Repository(DataLayerError::AlreadyExists)) => {
                tracing::debug!("Identifier already exists, fetching again");
                self.get_identifier(organisation, details).await
            }
            result => result,
        }
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_local_identifier(
        &self,
        name: String,
        request: CreateLocalIdentifierRequest,
        organisation: Organisation,
    ) -> Result<Identifier, ServiceError> {
        Ok(self
            .tx_manager
            .tx_with_config(
                async {
                    Ok::<_, ServiceError>(match request {
                        CreateLocalIdentifierRequest::Did(did_request) => {
                            self.create_local_did_identifier(name, did_request, organisation)
                                .await?
                        }
                        CreateLocalIdentifierRequest::Certificate(certificates) => {
                            self.create_local_certificate_identifier(
                                name,
                                certificates,
                                organisation,
                            )
                            .await?
                        }
                        CreateLocalIdentifierRequest::Key(key) => {
                            self.create_local_key_identifier(name, key, organisation)
                                .await?
                        }
                        CreateLocalIdentifierRequest::CertificateAuthority(
                            certificate_authorities,
                        ) => {
                            self.create_local_certificate_authority_identifier(
                                name,
                                certificate_authorities,
                                organisation,
                            )
                            .await?
                        }
                    })
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await??)
    }
}
