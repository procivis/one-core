use one_crypto::Hasher;
use one_crypto::hasher::sha256::SHA256;
use shared_types::{CertificateId, IdentifierId};
use time::OffsetDateTime;
use uuid::Uuid;
use x509_parser::pem::Pem;
use x509_parser::prelude::X509Certificate;

use super::dto::{
    CertificateResponseDTO, CertificateX509AttributesDTO, CreateCertificateRequestDTO,
};
use super::mapper::create_response_dto;
use super::{CertificateService, x509_extension};
use crate::model::certificate::{Certificate, CertificateRelations, CertificateState};
use crate::model::key::Key;
use crate::provider::key_algorithm::error::KeyAlgorithmProviderError;
use crate::service::error::{
    EntityNotFoundError, MissingProviderError, ServiceError, ValidationError,
};

impl CertificateService {
    pub async fn get_certificate(
        &self,
        id: CertificateId,
    ) -> Result<CertificateResponseDTO, ServiceError> {
        let certificate = self
            .certificate_repository
            .get(
                id,
                &CertificateRelations {
                    key: Default::default(),
                },
            )
            .await?
            .ok_or(EntityNotFoundError::Certificate(id))?;

        let (attributes, ..) = self.parse_pem_chain(certificate.chain.as_bytes(), None)?;

        Ok(create_response_dto(certificate, attributes))
    }

    pub(crate) async fn validate_and_prepare_certificate(
        &self,
        identifier_id: IdentifierId,
        request: CreateCertificateRequestDTO,
    ) -> Result<Certificate, ServiceError> {
        let key = self
            .key_repository
            .get_key(&request.key_id, &Default::default())
            .await?
            .ok_or(EntityNotFoundError::Key(request.key_id))?;

        let (attributes, subject_common_name) =
            self.parse_pem_chain(request.chain.as_bytes(), Some(&key))?;

        let name = match request.name {
            Some(name) => name,
            None => subject_common_name.ok_or_else(|| {
                ValidationError::CertificateParsingFailed("missing common-name".to_string())
            })?,
        };
        Ok(Certificate {
            id: Uuid::new_v4().into(),
            identifier_id,
            created_date: OffsetDateTime::now_utc(),
            last_modified: OffsetDateTime::now_utc(),
            expiry_date: attributes.not_after,
            name,
            chain: request.chain,
            state: CertificateState::Active,
            key: Some(key),
        })
    }

    fn parse_pem_chain(
        &self,
        pem_chain: &[u8],
        validate_with_expected_pub_key: Option<&Key>,
    ) -> Result<(CertificateX509AttributesDTO, Option<String>), ServiceError> {
        let mut result: Option<(CertificateX509AttributesDTO, Option<String>)> = None;
        let mut previous: Option<Pem> = None;
        for item in Pem::iter_from_buffer(pem_chain) {
            let pem =
                item.map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

            let current = pem
                .parse_x509()
                .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

            if result.is_none() {
                let attributes = parse_x509_attributes(&current, &pem.contents)?;
                let subject_common_name = current
                    .subject
                    .iter_common_name()
                    .next()
                    .and_then(|cn| cn.as_str().ok())
                    .map(ToString::to_string);

                let res = (attributes, subject_common_name);
                if let Some(expected_pub_key) = validate_with_expected_pub_key {
                    self.validate_subject_public_key(&current, expected_pub_key)?;
                    result = Some(res);
                } else {
                    return Ok(res);
                }
            }

            if !current.validity().is_valid() {
                return Err(ValidationError::CertificateNotValid.into());
            }

            if let Some(previous) = previous {
                // parent entry in the chain, validate signature
                let previous = previous
                    .parse_x509()
                    .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;
                previous
                    .verify_signature(Some(current.public_key()))
                    .map_err(|_| ValidationError::CertificateSignatureInvalid)?;
            }

            previous = Some(pem);
        }

        result.ok_or(
            ValidationError::CertificateParsingFailed("No certificates specified".to_string())
                .into(),
        )
    }

    fn validate_subject_public_key(
        &self,
        certificate: &X509Certificate,
        key: &Key,
    ) -> Result<(), ServiceError> {
        let key_algorithm = self
            .key_algorithm_provider
            .key_algorithm_from_name(&key.key_type)
            .ok_or_else(|| {
                MissingProviderError::KeyAlgorithmProvider(
                    KeyAlgorithmProviderError::MissingAlgorithmImplementation(
                        key.key_type.to_owned(),
                    ),
                )
            })?;

        let subject_public_key = key_algorithm
            .parse_raw(certificate.subject_pki.raw)
            .map_err(|err| ServiceError::ValidationError(err.to_string()))?;

        let subject_raw_public_key = subject_public_key.public_key_as_raw();
        if key.public_key != subject_raw_public_key {
            return Err(ValidationError::CertificateKeyNotMatching.into());
        }

        Ok(())
    }
}

fn parse_x509_attributes(
    certificate: &X509Certificate,
    der: &[u8],
) -> Result<CertificateX509AttributesDTO, ValidationError> {
    let validity = certificate.validity();

    let fingerprint = SHA256
        .hash(der)
        .map_err(|err| ValidationError::CertificateParsingFailed(err.to_string()))?;

    let extensions = certificate
        .extensions()
        .iter()
        .map(x509_extension::parse)
        .collect();

    Ok(CertificateX509AttributesDTO {
        serial_number: certificate.raw_serial_as_string(),
        not_before: validity.not_before.to_datetime(),
        not_after: validity.not_after.to_datetime(),
        issuer: certificate.issuer.to_string(),
        subject: certificate.subject.to_string(),
        fingerprint: hex::encode(fingerprint),
        extensions,
    })
}
