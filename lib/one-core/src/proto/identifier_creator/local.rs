use std::collections::{HashMap, HashSet};
use std::ops::Deref;

use shared_types::{DidId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;
use uuid::Uuid;

use super::Error;
use super::creator::IdentifierCreatorProto;
use crate::config::validator::did::validate_did_method;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::model::certificate::{Certificate, CertificateState};
use crate::model::did::Did;
use crate::model::identifier::{Identifier, IdentifierState, IdentifierType};
use crate::model::key::Key;
use crate::model::organisation::Organisation;
use crate::proto::certificate_validator::x509_extension::validate_ca;
use crate::proto::certificate_validator::{
    CertificateValidationOptions, CrlMode, EnforceKeyUsage, ParsedCertificate,
};
use crate::provider::key_algorithm::key::KeyHandle;
use crate::provider::signer::dto::{CreateSignatureRequest, Issuer};
use crate::repository::error::DataLayerError;
use crate::service::certificate::dto::CreateCertificateRequestDTO;
use crate::service::did::dto::CreateDidRequestDTO;
use crate::service::did::mapper::did_from_did_request;
use crate::service::did::service::{build_keys_request, generate_update_key};
use crate::service::did::validator::validate_request_amount_of_keys;
use crate::service::error::{EntityNotFoundError, MissingProviderError, ValidationError};
use crate::service::identifier::dto::CreateCertificateAuthorityRequestDTO;

impl IdentifierCreatorProto {
    pub(super) async fn create_local_did_identifier(
        &self,
        name: String,
        request: CreateDidRequestDTO,
        organisation: Organisation,
    ) -> Result<Identifier, Error> {
        let did = self
            .create_did_without_identifier(request, organisation.to_owned())
            .await?;

        let now = OffsetDateTime::now_utc();
        let identifier = Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name,
            organisation: Some(organisation),
            r#type: IdentifierType::Did,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            did: Some(did),
            key: None,
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.to_owned())
            .await
            .map_err(map_already_exists_error)?;

        Ok(identifier)
    }

    pub(super) async fn create_local_key_identifier(
        &self,
        name: String,
        key: Key,
        organisation: Organisation,
    ) -> Result<Identifier, Error> {
        if key.is_remote() {
            return Err(Error::KeyMustNotBeRemote(key.name));
        }

        if key
            .organisation
            .as_ref()
            .ok_or(Error::MappingError("missing organisation".to_string()))?
            .id
            != organisation.id
        {
            return Err(Error::MappingError("Organisation ID mismatch".to_string()));
        }

        let now = OffsetDateTime::now_utc();
        let identifier = Identifier {
            id: Uuid::new_v4().into(),
            created_date: now,
            last_modified: now,
            name,
            organisation: Some(organisation),
            r#type: IdentifierType::Key,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            did: None,
            key: Some(key),
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.to_owned())
            .await
            .map_err(map_already_exists_error)?;

        Ok(identifier)
    }

    pub(super) async fn create_local_certificate_identifier(
        &self,
        name: String,
        requests: Vec<CreateCertificateRequestDTO>,
        organisation: Organisation,
    ) -> Result<Identifier, Error> {
        let id = Uuid::new_v4().into();

        let mut certificates = vec![];
        for request in requests {
            certificates.push(
                self.validate_and_prepare_certificate(id, organisation.id, request)
                    .await?,
            );
        }

        let now = OffsetDateTime::now_utc();
        let identifier = Identifier {
            id,
            created_date: now,
            last_modified: now,
            name,
            organisation: Some(organisation),
            r#type: IdentifierType::Certificate,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            did: None,
            key: None,
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.to_owned())
            .await
            .map_err(map_already_exists_error)?;

        for certificate in certificates {
            self.certificate_repository
                .create(certificate)
                .await
                .map_err(|err| match err {
                    DataLayerError::AlreadyExists => Error::CertificateAlreadyExists,
                    e => e.error_while("creating certificate").into(),
                })?;
        }

        Ok(identifier)
    }

    pub(super) async fn create_local_certificate_authority_identifier(
        &self,
        name: String,
        requests: Vec<CreateCertificateAuthorityRequestDTO>,
        organisation: Organisation,
    ) -> Result<Identifier, Error> {
        let id = Uuid::new_v4().into();

        let mut certificates = vec![];
        for request in requests {
            certificates.push(
                self.validate_and_prepare_certificate_authority(id, organisation.id, request)
                    .await?,
            );
        }

        let now = OffsetDateTime::now_utc();
        let identifier = Identifier {
            id,
            created_date: now,
            last_modified: now,
            name,
            organisation: Some(organisation),
            r#type: IdentifierType::CertificateAuthority,
            is_remote: false,
            state: IdentifierState::Active,
            deleted_at: None,
            did: None,
            key: None,
            certificates: None,
        };
        self.identifier_repository
            .create(identifier.to_owned())
            .await
            .map_err(map_already_exists_error)?;

        for certificate in certificates {
            self.certificate_repository
                .create(certificate)
                .await
                .map_err(|err| match err {
                    DataLayerError::AlreadyExists => Error::CertificateAlreadyExists,
                    e => e.error_while("creating certificate").into(),
                })?;
        }

        Ok(identifier)
    }

    async fn create_did_without_identifier(
        &self,
        request: CreateDidRequestDTO,
        organisation: Organisation,
    ) -> Result<Did, Error> {
        if request.organisation_id != organisation.id {
            return Err(Error::MappingError("Organisation ID mismatch".to_string()));
        }

        validate_did_method(&request.did_method, &self.config.did)
            .error_while("validating did request")?;

        let did_method_key = &request.did_method;
        let did_method = self
            .did_method_provider
            .get_did_method(did_method_key)
            .ok_or(MissingProviderError::DidMethod(did_method_key.to_owned()))
            .error_while("getting did provider")?;

        validate_request_amount_of_keys(did_method.deref(), request.keys.to_owned())
            .error_while("validating did request")?;

        let keys = request.keys.to_owned();

        let key_ids = HashSet::<KeyId>::from_iter(
            [
                keys.authentication,
                keys.assertion_method,
                keys.key_agreement,
                keys.capability_invocation,
                keys.capability_delegation,
            ]
            .concat(),
        );

        let key_ids = key_ids.into_iter().collect::<Vec<_>>();
        let mut all_keys = self
            .key_repository
            .get_keys(&key_ids)
            .await
            .error_while("getting keys")?;

        let new_id = Uuid::new_v4();
        let new_did_id = DidId::from(new_id);

        let capabilities = did_method.get_capabilities();
        for key in &all_keys {
            if key.is_remote() {
                return Err(Error::KeyMustNotBeRemote(key.name.clone()));
            }
            let key_algorithm = key
                .key_algorithm_type()
                .and_then(|alg| self.key_algorithm_provider.key_algorithm_from_type(alg))
                .ok_or(ValidationError::InvalidKeyAlgorithm(
                    key.key_type.to_owned(),
                ))
                .error_while("getting key algorithm")?;

            if !capabilities
                .key_algorithms
                .contains(&key_algorithm.algorithm_type())
            {
                return Err(Error::DidMethodIncapableKeyAlgorithm {
                    key_algorithm: key.key_type.to_owned(),
                });
            }
        }

        let mut keys = build_keys_request(&request.keys, all_keys.clone())
            .error_while("building key request")?;

        let mut update_keys = None;
        if let Some(update_key_type) = capabilities.supported_update_key_types.first() {
            let update_key = generate_update_key(
                &request.name,
                new_did_id,
                organisation.clone(),
                *update_key_type,
                &*self.key_provider,
            )
            .await
            .error_while("generating update key")?;

            update_keys = Some(vec![update_key]);
            keys.update_keys = update_keys.clone();
        }

        let did_value = did_method
            .create(Some(new_did_id), &request.params, Some(keys.clone()))
            .await
            .error_while("creating DID")?;

        if let Some(update_keys) = update_keys {
            for key in update_keys {
                self.key_repository
                    .create_key(key.clone())
                    .await
                    .error_while("creating key")?;
                all_keys.push(key);
            }
        }

        let mut key_reference_mapping: HashMap<KeyId, String> = HashMap::new();
        for key in all_keys {
            let reference = did_method
                .get_reference_for_key(&key)
                .error_while("getting DID key reference")?;
            key_reference_mapping.insert(key.id, reference);
        }

        let now = OffsetDateTime::now_utc();
        let did = did_from_did_request(
            new_did_id,
            request,
            organisation,
            did_value,
            keys,
            now,
            key_reference_mapping,
        )
        .error_while("creating did model")?;
        let did_value = did.did.clone();

        self.did_repository
            .create_did(did.to_owned())
            .await
            .map_err(|err| match err {
                DataLayerError::AlreadyExists => Error::DidValueAlreadyExists(did_value),
                err => err.error_while("creating did").into(),
            })?;

        Ok(did)
    }

    async fn validate_and_prepare_certificate(
        &self,
        identifier_id: IdentifierId,
        organisation_id: OrganisationId,
        request: CreateCertificateRequestDTO,
    ) -> Result<Certificate, Error> {
        let key = self
            .key_repository
            .get_key(&request.key_id, &Default::default())
            .await
            .error_while("getting key")?
            .ok_or(EntityNotFoundError::Key(request.key_id))
            .error_while("getting key")?;

        let ParsedCertificate {
            attributes,
            subject_common_name,
            public_key,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                &request.chain,
                CertificateValidationOptions::signature_and_revocation(Some(vec![
                    EnforceKeyUsage::DigitalSignature,
                ])),
            )
            .await
            .error_while("parsing PEM chain")?;

        validate_subject_public_key(&public_key, &key)?;

        let name = match request.name {
            Some(name) => name,
            None => subject_common_name.ok_or(Error::MissingCertificateCommonName)?,
        };

        Ok(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: Some(organisation_id),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: attributes.not_after,
            name,
            chain: request.chain,
            fingerprint: attributes.fingerprint,
            state: CertificateState::Active,
            key: Some(key),
        })
    }

    async fn validate_and_prepare_certificate_authority(
        &self,
        identifier_id: IdentifierId,
        organisation_id: OrganisationId,
        request: CreateCertificateAuthorityRequestDTO,
    ) -> Result<Certificate, Error> {
        let key = self
            .key_repository
            .get_key(&request.key_id, &Default::default())
            .await
            .error_while("getting key")?
            .ok_or(EntityNotFoundError::Key(request.key_id))
            .error_while("getting key")?;

        let chain = match (request.chain, request.self_signed) {
            (Some(chain), None) => chain,
            (None, Some(self_signed)) => {
                let csr = self
                    .csr_creator
                    .create_csr(key.clone(), self_signed.content.clone().into())
                    .await
                    .error_while("creating CSR")?;
                let signer = self
                    .signer_provider
                    .get(&self_signed.signer)
                    .ok_or(MissingProviderError::Signer(self_signed.signer.clone()))
                    .error_while("getting signer")?;
                signer
                    .sign(
                        Issuer::Key(Box::new(key.clone())),
                        CreateSignatureRequest {
                            data: serde_json::json!({"csr": csr}),
                            validity_start: self_signed.validity_start,
                            validity_end: self_signed.validity_end,
                        },
                    )
                    .await
                    .error_while("parsing PEM chain")?
                    .result
            }
            _ => {
                return Err(Error::InvalidCertificateAuthorityIdentifierInput);
            }
        };

        let ParsedCertificate {
            attributes,
            subject_common_name,
            public_key,
            ..
        } = self
            .certificate_validator
            .parse_pem_chain(
                &chain,
                CertificateValidationOptions {
                    require_root_termination: true,
                    integrity_check: true,
                    validity_check: Some(CrlMode::X509),
                    required_leaf_cert_key_usage: Default::default(),
                    leaf_only_extensions: Default::default(),
                    leaf_validations: vec![validate_ca],
                },
            )
            .await
            .error_while("parsing PEM chain")?;

        validate_subject_public_key(&public_key, &key)?;

        let name = match request.name {
            Some(name) => name,
            None => subject_common_name.ok_or(Error::MissingCertificateCommonName)?,
        };

        Ok(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            organisation_id: Some(organisation_id),
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: attributes.not_after,
            name,
            chain,
            fingerprint: attributes.fingerprint,
            state: CertificateState::Active,
            key: Some(key),
        })
    }
}

fn map_already_exists_error(error: DataLayerError) -> Error {
    match error {
        DataLayerError::AlreadyExists => Error::IdentifierAlreadyExists,
        e => e.error_while("creating identifier").into(),
    }
}

fn validate_subject_public_key(
    subject_public_key: &KeyHandle,
    expected_key: &Key,
) -> Result<(), Error> {
    let subject_raw_public_key = subject_public_key.public_key_as_raw();
    if expected_key.public_key != subject_raw_public_key {
        return Err(Error::CertificateKeyNotMatching);
    }

    Ok(())
}
