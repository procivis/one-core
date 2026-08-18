use standardized_types::etsi_119_475::registration_certificate::Payload;

use crate::proto::jwt::model::JWTPayload;
use crate::proto::wrp_validator::model::WRPPayload;
use crate::util::access_cert_parser::EtsiParsedAccessCert;

pub(crate) enum TrustDetails {
    Etsi {
        wrp: WalletRelyingPartyDetails,
        access_certificate: EtsiParsedAccessCert,
    },
}

pub(crate) enum WalletRelyingPartyDetails {
    RegistrationCertificate(JWTPayload<Payload>),
    NationalRegistryInfo(JWTPayload<WRPPayload>),
}
