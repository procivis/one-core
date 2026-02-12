use one_dto_mapper::convert_inner;

use super::dto::CertificateResponseDTO;
use crate::error::ContextWithErrorCode;
use crate::model::certificate::Certificate;
use crate::proto::certificate_validator::parse::parse_chain_to_x509_attributes;
use crate::service::error::ServiceError;

impl TryFrom<Certificate> for CertificateResponseDTO {
    type Error = ServiceError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let x509_attributes = parse_chain_to_x509_attributes(certificate.chain.as_bytes())
            .error_while("parsing PEM chain")?;
        Ok(Self {
            id: certificate.id,
            identifier_id: certificate.identifier_id,
            created_date: certificate.created_date,
            last_modified: certificate.last_modified,
            state: certificate.state,
            name: certificate.name,
            chain: certificate.chain,
            key: convert_inner(certificate.key),
            x509_attributes,
            organisation_id: certificate.organisation_id,
        })
    }
}
