use shared_types::{CertificateId, IdentifierId, KeyId, OrganisationId};
use time::OffsetDateTime;

use crate::model::certificate::CertificateState;
use crate::service::key::dto::{
    KeyGenerateCSRRequestProfile, KeyGenerateCSRRequestSubjectDTO, KeyListItemResponseDTO,
};

#[derive(Clone, Debug)]
pub struct CreateCertificateRequestDTO {
    pub name: Option<String>,
    pub chain: Option<String>,
    pub key_id: KeyId,
    pub content: Option<CreateCertificateContentDTO>,
}

#[derive(Clone, Debug)]
pub struct CreateCertificateContentDTO {
    pub profile: KeyGenerateCSRRequestProfile,
    pub subject: KeyGenerateCSRRequestSubjectDTO,
    pub certificate_authority: CreateCertificateCaDTO,
    pub signer: String,
    pub validity_start: Option<OffsetDateTime>,
    pub validity_end: Option<OffsetDateTime>,
}

#[derive(Clone, Debug)]
pub struct CreateCertificateCaDTO {
    pub identifier_id: IdentifierId,
    pub certificate_id: Option<CertificateId>,
}

#[derive(Clone, Debug)]
pub struct CertificateX509AttributesDTO {
    pub serial_number: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub issuer: String,
    pub subject: String,
    pub fingerprint: String,
    pub extensions: Vec<CertificateX509ExtensionDTO>,
}

#[derive(Clone, Debug)]
pub struct CertificateX509ExtensionDTO {
    pub oid: String,
    pub value: String,
    pub critical: bool,
}

#[derive(Clone, Debug)]
pub struct CertificateResponseDTO {
    pub id: CertificateId,
    pub identifier_id: IdentifierId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub state: CertificateState,
    pub name: String,
    pub chain: String,
    pub key: Option<KeyListItemResponseDTO>,
    pub x509_attributes: CertificateX509AttributesDTO,
    pub organisation_id: Option<OrganisationId>,
}
