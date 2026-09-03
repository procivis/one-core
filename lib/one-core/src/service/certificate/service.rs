use coset::CborSerializable;
use ct_codecs::{Base64, Decoder};
use shared_types::CertificateId;

use super::CertificateService;
use super::dto::{CertificateFormatEnum, CertificateResponseDTO};
use super::error::CertificateServiceError;
use super::mapper::certificate_to_response_dto;
use crate::error::{ContextWithErrorCode, ErrorCodeMixinExt};
use crate::mapper::x509::{pem_chain_into_der_chain, pem_chain_into_x5c};
use crate::model::identifier::IdentifierType;
use crate::provider::credential_formatter::mdoc_formatter::util::Bstr;
use crate::repository::error::{DataLayerError, EntityKind};
use crate::validator::throw_if_org_id_not_matching_session;

/// Certificates are soft-deleted, so a "found but deleted" row must be reported the same way as
/// a genuinely missing one (same `EntityNotFound`/BR_0223 shape the repository itself uses).
fn certificate_not_found(id: CertificateId) -> CertificateServiceError {
    DataLayerError::EntityNotFound {
        kind: EntityKind::Certificate,
        id: id.into(),
    }
    .error_while("getting certificate")
    .into()
}

impl CertificateService {
    pub async fn get_certificate(
        &self,
        id: CertificateId,
    ) -> Result<CertificateResponseDTO, CertificateServiceError> {
        let certificate = self
            .certificate_repository
            .get(id)
            .await
            .error_while("getting certificate")?;

        if certificate.deleted_at.is_some() {
            return Err(certificate_not_found(id));
        }

        throw_if_org_id_not_matching_session(
            certificate.organisation.id_ref(),
            &*self.session_provider,
        )
        .error_while("checking session")?;

        certificate_to_response_dto(certificate).await
    }

    pub async fn get_certificate_authority(
        &self,
        id: CertificateId,
    ) -> Result<Vec<u8>, CertificateServiceError> {
        let certificate = self
            .certificate_repository
            .get(id)
            .await
            .error_while("getting certificate")?;

        if certificate.deleted_at.is_some() {
            return Err(certificate_not_found(id));
        }

        let identifier = self
            .identifier_repository
            .get(certificate.identifier_id)
            .await
            .error_while("getting identifier")?;

        if identifier.data.r#type() != IdentifierType::CertificateAuthority {
            tracing::info!("Invalid identifier type: {}", identifier.data.r#type());
            return Err(certificate_not_found(id));
        }

        let x5c = pem_chain_into_x5c(&certificate.chain).error_while("parsing PEM chain")?;

        let base64_encoded = x5c.first().ok_or(CertificateServiceError::MappingError(
            "Empty chain".to_string(),
        ))?;

        Base64::decode_to_vec(base64_encoded, None)
            .map_err(|e| CertificateServiceError::MappingError(e.to_string()))
    }

    pub async fn get_certificate_content(
        &self,
        id: CertificateId,
        format: CertificateFormatEnum,
    ) -> Result<Vec<u8>, CertificateServiceError> {
        let certificate = self
            .certificate_repository
            .get(id)
            .await
            .error_while("getting certificate")?;

        if certificate.deleted_at.is_some() {
            return Err(certificate_not_found(id));
        }

        let identifier = self
            .identifier_repository
            .get(certificate.identifier_id)
            .await
            .error_while("getting identifier")?;

        if identifier.data.r#type() != IdentifierType::Certificate {
            tracing::info!("Invalid identifier type: {}", identifier.data.r#type());
            return Err(certificate_not_found(id));
        }

        Ok(match format {
            CertificateFormatEnum::Pem => certificate.chain.as_bytes().to_vec(),
            CertificateFormatEnum::CoseX509 => {
                let der_chain = pem_chain_into_der_chain(&certificate.chain)
                    .error_while("coverting PEM chain")?;
                let result = ciborium::Value::Array(
                    der_chain
                        .into_iter()
                        .map(|der| ciborium::Value::from(Bstr(der)))
                        .collect(),
                );
                result
                    .to_vec()
                    .map_err(|e| CertificateServiceError::MappingError(e.to_string()))?
            }
        })
    }
}
