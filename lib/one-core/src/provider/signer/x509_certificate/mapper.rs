use asn1_rs::{FromDer, Oid, Tag};
use one_crypto::Hasher;
use one_crypto::hasher::sha1::SHA1;
use rcgen::string::{BmpString, UniversalString};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, KeyIdMethod, KeyUsagePurpose,
    PublicKeyData, SignatureAlgorithm,
};
use x509_parser::prelude::{GeneralName, KeyUsage, ParsedExtension};
use x509_parser::x509::X509Name;

use crate::proto::csr_creator::{
    CsrRequestIssuerAlternativeName, IssuerAlternativeNameType, OID_EXTENDED_KEY_USAGE_ISO_MDL_DS,
    prepare_extended_key_usage_extension_iso_mdl_ds, prepare_issuer_alternative_name_extension,
};
use crate::provider::signer::dto::CreateSignatureRequest;
use crate::provider::signer::x509_certificate::RequestData;

#[derive(Debug, thiserror::Error)]
pub(super) enum CSRError {
    #[error("Invalid OID")]
    InvalidOID,
    #[error("Invalid subject tag: `{0}`")]
    InvalidSubjectTag(Tag),

    #[error("Disallowed key usage: `{0}`")]
    DisallowedKeyUsage(KeyUsage),
    #[error("Disallowed extension: `{0}`")]
    DisallowedExtension(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("PEM error: {0}")]
    Pem(#[from] pem::PemError),
    #[error("X509 nom error: `{0}`")]
    X509Nom(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("X509 error: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("rcgen error: {0}")]
    RCGen(#[from] rcgen::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("Hasher error: {0}")]
    Hasher(#[from] one_crypto::HasherError),
}

pub(super) fn params_from_request(
    request: CreateSignatureRequest,
    self_signing: bool,
) -> Result<(CertificateParams, PublicKey), CSRError> {
    let request_data: RequestData = serde_json::from_value(request.data)?;

    let csr = pem::parse(&request_data.csr)?;
    let csr =
        x509_parser::certification_request::X509CertificationRequest::from_der(csr.contents())?.1;
    csr.verify_signature()?;

    let info = &csr.certification_request_info;

    let public_key = PublicKey {
        alg: SignatureAlgorithm::from_oid(&oid_to_vec(&csr.signature_algorithm.algorithm)?)?,
        raw_key: info.subject_pki.subject_public_key.data.to_vec(),
    };

    let mut params = CertificateParams::default();
    parse_subject(&mut params.distinguished_name, &info.subject)?;

    if let Some(extensions) = csr.requested_extensions() {
        for extension in extensions {
            parse_extension(&mut params, extension, self_signing)?;
        }
    }

    // ISO 18013-5 specifies to use SHA-1 hash
    let key_id = SHA1.hash(public_key.der_bytes())?;
    params.key_identifier_method = KeyIdMethod::PreSpecified(key_id);

    Ok((params, public_key))
}

fn parse_subject<'a>(
    output: &mut DistinguishedName,
    subject: &X509Name<'a>,
) -> Result<(), CSRError> {
    for attr in subject.iter_attributes() {
        let value = attr.attr_value();
        let data = value.data;
        let try_str = |data| std::str::from_utf8(data);
        let dn_value = match value.header.tag() {
            Tag::BmpString => DnValue::BmpString(BmpString::from_utf16be(data.to_vec())?),
            Tag::Ia5String => DnValue::Ia5String(try_str(data)?.try_into()?),
            Tag::PrintableString => DnValue::PrintableString(try_str(data)?.try_into()?),
            Tag::T61String => DnValue::TeletexString(try_str(data)?.try_into()?),
            Tag::UniversalString => {
                DnValue::UniversalString(UniversalString::from_utf32be(data.to_vec())?)
            }
            Tag::Utf8String => DnValue::Utf8String(try_str(data)?.to_owned()),
            tag => {
                return Err(CSRError::InvalidSubjectTag(tag));
            }
        };

        output.push(DnType::from_oid(&oid_to_vec(attr.attr_type())?), dn_value);
    }

    Ok(())
}

#[tracing::instrument(level = "debug", skip(output), err(Debug, level = "warn"))]
fn parse_extension<'a>(
    output: &mut CertificateParams,
    extension: &ParsedExtension<'a>,
    self_signing: bool,
) -> Result<(), CSRError> {
    match extension {
        // limited Key Usage allowed
        ParsedExtension::KeyUsage(key_usage) => {
            if key_usage.crl_sign() {
                output.key_usages.push(KeyUsagePurpose::CrlSign);
            }
            if key_usage.key_cert_sign() {
                output.key_usages.push(KeyUsagePurpose::KeyCertSign);
            }
            if key_usage.digital_signature() {
                output.key_usages.push(KeyUsagePurpose::DigitalSignature);
            }

            if key_usage.non_repudiation()
                || key_usage.key_encipherment()
                || key_usage.data_encipherment()
                || key_usage.key_agreement()
                || key_usage.encipher_only()
                || key_usage.decipher_only()
            {
                return Err(CSRError::DisallowedKeyUsage(*key_usage));
            }
        }

        // Extended Key Usage support for ISO mDL document signer
        ParsedExtension::ExtendedKeyUsage(eku) => {
            if eku.any
                || eku.server_auth
                || eku.client_auth
                || eku.code_signing
                || eku.email_protection
                || eku.time_stamping
                || eku.ocsp_signing
            {
                return Err(CSRError::DisallowedExtension(format!("{extension:?}")));
            }

            for oid in &eku.other {
                if oid_to_vec(oid)? == OID_EXTENDED_KEY_USAGE_ISO_MDL_DS {
                    output
                        .custom_extensions
                        .push(prepare_extended_key_usage_extension_iso_mdl_ds());
                } else {
                    return Err(CSRError::DisallowedExtension(format!("{extension:?}")));
                }
            }
        }

        // Issuer Alternative Name support for self-signed root CA
        ParsedExtension::IssuerAlternativeName(ian)
            if self_signing && ian.general_names.len() == 1 =>
        {
            let name = match ian.general_names.first() {
                Some(GeneralName::RFC822Name(email)) => CsrRequestIssuerAlternativeName {
                    r#type: IssuerAlternativeNameType::Email,
                    name: email.to_string(),
                },
                Some(GeneralName::URI(uri)) => CsrRequestIssuerAlternativeName {
                    r#type: IssuerAlternativeNameType::Uri,
                    name: uri.to_string(),
                },
                _ => {
                    return Err(CSRError::DisallowedExtension(format!("{extension:?}")));
                }
            };

            output
                .custom_extensions
                .push(prepare_issuer_alternative_name_extension(name));
        }

        _ => {
            return Err(CSRError::DisallowedExtension(format!("{extension:?}")));
        }
    };

    Ok(())
}

pub(super) struct PublicKey {
    alg: &'static SignatureAlgorithm,
    raw_key: Vec<u8>,
}

impl PublicKeyData for PublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw_key
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        self.alg
    }
}

fn oid_to_vec<'a>(oid: &Oid<'a>) -> Result<Vec<u64>, CSRError> {
    Ok(oid.iter().ok_or(CSRError::InvalidOID)?.collect())
}
