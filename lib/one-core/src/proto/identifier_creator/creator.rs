use std::sync::Arc;

use futures::FutureExt;
use shared_types::{BlobId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::mapper::build_identifier_translations;
use super::{
    CreateLocalIdentifierRequestParams, CreateLocalIdentifierRequestType, Error, IdentifierCreator,
    IdentifierName, IdentifierTranslations, RemoteIdentifierOutcome, RemoteIdentifierRelation,
};
use crate::config::core_config::{BlobStorageType, CoreConfig};
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, ErrorCodeMixinExt};
use crate::model::blob::{Blob, BlobType};
use crate::model::certificate::{
    Certificate, CertificateFilterValue, CertificateListQuery, CertificateState,
};
use crate::model::identifier::{
    Identifier, IdentifierData, IdentifierState, IdentifierType, UpdateIdentifierRequest,
};
use crate::model::list_filter::ListFilterValue;
use crate::model::localized_text::{LocalizedText, LocalizedTextEntityType, LocalizedTextField};
use crate::model::organisation::Organisation;
use crate::model::relation::RelatedVec;
use crate::proto::certificate_validator::x509_extension::{validate_ca, validate_not_ca};
use crate::proto::certificate_validator::{
    CertificateValidationOptions, LeafValidation, ParsedCertificate,
};
use crate::proto::csr_creator::CsrCreator;
use crate::proto::transaction_manager::{IsolationLevel, TransactionManager};
use crate::provider::blob_storage::provider::BlobStorageProvider;
use crate::provider::credential_formatter::model::{CertificateDetails, IdentifierDetails};
use crate::provider::did_method::provider::DidMethodProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::signer::provider::SignerProvider;
use crate::repository::certificate_repository::CertificateRepository;
use crate::repository::did_repository::DidRepository;
use crate::repository::error::DataLayerError;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
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
    pub(super) signer_provider: Arc<dyn SignerProvider>,
    pub(super) csr_creator: Arc<dyn CsrCreator>,
    pub(super) blob_storage_provider: Arc<dyn BlobStorageProvider>,
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
        signer_provider: Arc<dyn SignerProvider>,
        blob_storage_provider: Arc<dyn BlobStorageProvider>,
        csr_creator: Arc<dyn CsrCreator>,
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
            signer_provider,
            blob_storage_provider,
            csr_creator,
            config,
            tx_manager,
        }
    }

    pub(super) async fn persist_logo(
        &self,
        logo: String,
        now: OffsetDateTime,
    ) -> Result<BlobId, Error> {
        let blob_storage = self
            .blob_storage_provider
            .get_blob_storage(BlobStorageType::Db)?;
        let blob_id = Uuid::new_v4().into();
        blob_storage
            .create(Blob {
                id: blob_id,
                created_date: now,
                last_modified: now,
                value: logo.into_bytes(),
                r#type: BlobType::IdentifierLogo,
            })
            .await
            .error_while("saving logo blob")?;
        Ok(blob_id)
    }
}

#[async_trait::async_trait]
impl IdentifierCreator for IdentifierCreatorProto {
    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn get_or_create_remote_identifier(
        &self,
        organisation: &Organisation,
        details: &IdentifierDetails,
        name: IdentifierName,
        autogenerated: bool,
        translations: Option<IdentifierTranslations>,
        logo: Option<String>,
    ) -> Result<(Identifier, RemoteIdentifierRelation), Error> {
        let result = self
            .tx_manager
            .tx_with_config(
                async {
                    let (identifier, relation) = match details {
                        IdentifierDetails::Did(did_value) => {
                            let (did, identifier) = self
                                .get_or_create_did_and_identifier(
                                    organisation,
                                    did_value,
                                    name,
                                    autogenerated,
                                )
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
                                    name,
                                    autogenerated,
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
                                    organisation,
                                    public_key_jwk,
                                    name,
                                    autogenerated,
                                )
                                .await?;
                            (identifier, RemoteIdentifierRelation::Key(key))
                        }
                    };
                    // Nothing from the issuer display to persist.
                    if translations.is_none() && logo.is_none() {
                        return Ok((identifier, relation));
                    }

                    let now = crate::clock::now_utc();
                    let mut update = UpdateIdentifierRequest::default();

                    // Translations are refreshed from the issuer metadata on every issuance, but only
                    // written when a row is new or its value changed.
                    if let Some(translations) = translations {
                        let desired_texts = build_identifier_translations(
                            identifier.id,
                            &identifier.name,
                            Some(translations),
                            now,
                            &self.config.global_settings.default_language,
                        );
                        let current_texts = identifier
                            .translations
                            .as_ref()
                            .await
                            .error_while("loading identifier translations")?
                            .to_owned();
                        let texts_changed = desired_texts.iter().any(|desired| {
                            !current_texts.iter().any(|current| {
                                current.field == desired.field
                                    && current.lang == desired.lang
                                    && current.value == desired.value
                            })
                        });
                        if texts_changed {
                            update.translations = Some(desired_texts);
                        }
                    }

                    // The logo is written once, when the identifier does not have one yet; it is never
                    // refreshed.
                    if let Some(logo) = logo
                        && identifier.logo.is_none()
                    {
                        let logo_id = self.persist_logo(logo, now).await?;
                        update.logo = Some(Some(logo_id));
                    }

                    if update.translations.is_none() && update.logo.is_none() {
                        return Ok((identifier, relation));
                    }

                    self.identifier_repository
                        .update(&identifier.id, update)
                        .await
                        .error_while("updating remote issuer identifier display")?;
                    let identifier = self
                        .identifier_repository
                        .get(identifier.id)
                        .await
                        .error_while("reloading remote issuer identifier")?;
                    Ok::<_, Error>((identifier, relation))
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating remote identifier")?;

        let (identifier, relation) = match result {
            Err(error) if error.error_code() == ErrorCode::BR_0357 => {
                tracing::debug!("Identifier already exists, fetching again");
                self.find_identifier(organisation, details)
                    .await?
                    .ok_or(Error::MappingError(
                        "Identifier disappeared after uniqueness conflict".to_string(),
                    ))?
            }
            result => result?,
        };

        Ok((identifier, relation))
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_remote_certificate_identifier(
        &self,
        organisation: Organisation,
        name: String,
        chains: Vec<String>,
        identifier_type: IdentifierType,
    ) -> Result<RemoteIdentifierOutcome, Error> {
        if chains.is_empty() {
            return Err(Error::InvalidCertificateInput);
        }

        let leaf_validations: Vec<LeafValidation> = match identifier_type {
            IdentifierType::CertificateAuthority => vec![validate_ca],
            _ => vec![validate_not_ca],
        };

        self.tx_manager
            .tx_with_config(
                async move {
                    let identifier_id = IdentifierId::from(Uuid::new_v4());
                    let now = crate::clock::now_utc();
                    let mut prepared: Vec<Certificate> = Vec::with_capacity(chains.len());

                    for chain in chains {
                        let ParsedCertificate {
                            attributes,
                            subject_common_name,
                            ..
                        } = self
                            .certificate_validator
                            .parse_pem_chain(
                                &chain,
                                CertificateValidationOptions {
                                    leaf_validations: leaf_validations.clone(),
                                    ..CertificateValidationOptions::signature_and_revocation(None)
                                },
                            )
                            .await
                            .error_while("parsing pem chain")?;

                        let existing = self
                            .certificate_repository
                            .list(CertificateListQuery {
                                filtering: Some(
                                    CertificateFilterValue::Fingerprint(
                                        attributes.fingerprint.clone(),
                                    )
                                    .condition()
                                        & CertificateFilterValue::Deleted(false)
                                        & CertificateFilterValue::OrganisationId(organisation.id)
                                            .condition(),
                                ),
                                ..Default::default()
                            })
                            .await
                            .error_while("looking up certificate")?;

                        if let Some(certificate) = existing.values.into_iter().next() {
                            return Ok(RemoteIdentifierOutcome::AlreadyExists(
                                certificate.identifier_id,
                            ));
                        }

                        let cert = Certificate {
                            id: Uuid::new_v4().into(),
                            identifier_id,
                            organisation: organisation.clone().into(),
                            created_date: now,
                            last_modified: now,
                            deleted_at: None,
                            expiry_date: attributes.not_after,
                            name: subject_common_name.unwrap_or_else(|| name.clone()),
                            chain,
                            fingerprint: attributes.fingerprint,
                            state: CertificateState::Active,
                            roles: vec![],
                            key: None,
                        };

                        if prepared.iter().any(|c| {
                            c.fingerprint == cert.fingerprint
                                || (c.name == cert.name && c.expiry_date == cert.expiry_date)
                        }) {
                            return Err(Error::ConflictingCertificates);
                        }

                        prepared.push(cert);
                    }

                    let certificates = RelatedVec::from(prepared.clone());
                    let data = match identifier_type {
                        IdentifierType::CertificateAuthority => {
                            IdentifierData::CertificateAuthority(certificates)
                        }
                        _ => IdentifierData::Certificate(certificates),
                    };
                    let identifier = Identifier {
                        id: identifier_id,
                        created_date: now,
                        last_modified: now,
                        name: name.clone(),
                        data,
                        is_remote: true,
                        state: IdentifierState::Active,
                        deleted_at: None,
                        autogenerated: false,
                        logo: None,
                        organisation: organisation.into(),
                        trust_information: Default::default(),
                        translations: default_name_translation(
                            identifier_id,
                            name,
                            now,
                            &self.config.global_settings.default_language,
                        )
                        .into(),
                    };
                    self.identifier_repository
                        .create(identifier)
                        .await
                        .map_err(|err| match err {
                            DataLayerError::AlreadyExists => Error::IdentifierAlreadyExists,
                            e => e.error_while("creating identifier").into(),
                        })?;

                    for certificate in prepared {
                        self.certificate_repository
                            .create(certificate)
                            .await
                            .map_err(|err| match err {
                                DataLayerError::AlreadyExists => Error::CertificateAlreadyExists,
                                e => e.error_while("creating certificate").into(),
                            })?;
                    }

                    Ok(RemoteIdentifierOutcome::Created(identifier_id))
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating remote certificate identifier")?
    }

    #[tracing::instrument(level = "debug", skip_all, err(level = "warn"))]
    async fn create_local_identifier(
        &self,
        params: CreateLocalIdentifierRequestParams,
        r#type: CreateLocalIdentifierRequestType,
    ) -> Result<Identifier, Error> {
        Ok(self
            .tx_manager
            .tx_with_config(
                async {
                    Ok::<_, Error>(match r#type {
                        CreateLocalIdentifierRequestType::Did(did_request) => {
                            self.create_local_did_identifier(did_request, params)
                                .await?
                        }
                        CreateLocalIdentifierRequestType::Certificate(certificates) => {
                            self.create_local_certificate_identifier(certificates, params)
                                .await?
                        }
                        CreateLocalIdentifierRequestType::Key(key) => {
                            self.create_local_key_identifier(key, params).await?
                        }
                        CreateLocalIdentifierRequestType::CertificateAuthority(
                            certificate_authorities,
                        ) => {
                            self.create_local_certificate_authority_identifier(
                                certificate_authorities,
                                params,
                            )
                            .await?
                        }
                    })
                }
                .boxed(),
                Some(IsolationLevel::ReadCommitted),
                None,
            )
            .await
            .error_while("creating local identifier")??)
    }
}

pub(crate) fn default_name_translation(
    id: IdentifierId,
    name: String,
    now: time::OffsetDateTime,
    default_language: &str,
) -> Vec<LocalizedText> {
    vec![LocalizedText {
        entity_id: id.into(),
        field: LocalizedTextField::Name,
        created_date: now,
        last_modified: now,
        lang: default_language.to_string(),
        value: name,
        entity_type: LocalizedTextEntityType::Identifier,
    }]
}
