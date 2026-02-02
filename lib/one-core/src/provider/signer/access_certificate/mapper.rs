use rcgen::string::Ia5String;
use rcgen::{CertificateSigningRequestParams, DistinguishedName, DnType, PublicKey};

use crate::provider::signer::access_certificate::{AccessCertificatePolicy, RequestData};
use crate::provider::signer::error::SignerError;

pub(super) fn validated_pubkey_from_csr(csr: &str) -> Result<PublicKey, SignerError> {
    let csr = CertificateSigningRequestParams::from_pem(csr)
        .map_err(|e| SignerError::InvalidPayload(Box::new(e)))?;
    Ok(csr.public_key)
}

pub(super) fn request_to_distinguished_name(
    request: RequestData,
) -> Result<DistinguishedName, SignerError> {
    let mut dn = DistinguishedName::new();
    const OID_SURNAME: [u64; 4] = [2, 5, 4, 4];
    const OID_GIVEN_NAME: [u64; 4] = [2, 5, 4, 42];
    const OID_ORG_ID: [u64; 4] = [2, 5, 4, 97];

    dn.push(DnType::CountryName, request.country_name);
    dn.push(
        DnType::CustomDnType(OID_ORG_ID.to_vec()),
        request.organization_identifier,
    );
    if let Some(cn) = request.common_name {
        dn.push(DnType::CommonName, cn)
    }

    match &request.policy {
        AccessCertificatePolicy::NaturalPerson => {
            if request.organization_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "organizationName is not allowed for natural person"
                        .to_string()
                        .into(),
                ));
            }
            let Some(given_name) = request.given_name else {
                return Err(SignerError::InvalidPayload(
                    "givenName is required for natural person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(DnType::CustomDnType(OID_GIVEN_NAME.to_vec()), given_name);
            let Some(family_name) = request.family_name else {
                return Err(SignerError::InvalidPayload(
                    "familyName is required for natural person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(DnType::CustomDnType(OID_SURNAME.to_vec()), family_name)
        }
        AccessCertificatePolicy::LegalPerson => {
            if request.given_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "givenName is not allowed for legal person"
                        .to_string()
                        .into(),
                ));
            }
            if request.family_name.is_some() {
                return Err(SignerError::InvalidPayload(
                    "familyName is not allowed for legal person"
                        .to_string()
                        .into(),
                ));
            }
            let Some(organization_name) = request.organization_name else {
                return Err(SignerError::InvalidPayload(
                    "organizationName is required for legal person"
                        .to_string()
                        .into(),
                ));
            };
            dn.push(DnType::OrganizationName, organization_name)
        }
    }
    Ok(dn)
}

pub(super) fn to_ia5(string: String) -> Result<Ia5String, SignerError> {
    string
        .try_into()
        .map_err(|err| SignerError::InvalidPayload(Box::new(err)))
}
