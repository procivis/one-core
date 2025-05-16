use one_dto_mapper::convert_inner;

use super::dto::{CertificateResponseDTO, CertificateX509AttributesDTO};
use crate::model::certificate::Certificate;

pub(super) fn create_response_dto(
    certificate: Certificate,
    x509_attributes: CertificateX509AttributesDTO,
) -> CertificateResponseDTO {
    CertificateResponseDTO {
        id: certificate.id,
        created_date: certificate.created_date,
        last_modified: certificate.last_modified,
        name: certificate.name,
        state: certificate.state,
        chain: certificate.chain,
        key: convert_inner(certificate.key),
        x509_attributes,
        organisation_id: certificate.organisation.map(|organisation| organisation.id),
    }
}
