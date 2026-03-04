use asn1_rs::{FromDer, Oid, Tag};
use one_crypto::Hasher;
use one_crypto::hasher::sha1::SHA1;
use rcgen::string::{BmpString, UniversalString};
use rcgen::{
    CertificateParams, CustomExtension, DistinguishedName, DnType, DnValue, KeyIdMethod,
    KeyUsagePurpose, PublicKeyData, SignatureAlgorithm,
};
use x509_parser::prelude::{KeyUsage, ParsedExtension};
use x509_parser::x509::X509Name;

use super::dto::{
    IssuerAlternativeNameRequest, IssuerAlternativeNameType, KeyIdDerivation, SelfSignedRequest,
};
use crate::proto::csr_creator::{
    OID_EXTENDED_KEY_USAGE_ISO_MDL_DS, prepare_distinguished_name,
    prepare_extended_key_usage_extension_iso_mdl_ds,
};

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
}

pub(super) fn get_key_id_method<T: PublicKeyData>(
    public_key: &T,
    key_id_derivation: &KeyIdDerivation,
) -> Result<KeyIdMethod, one_crypto::HasherError> {
    Ok(match key_id_derivation {
        KeyIdDerivation::Sha1 => {
            let key_id = SHA1.hash(public_key.der_bytes())?;
            KeyIdMethod::PreSpecified(key_id)
        }
        KeyIdDerivation::Sha256 => KeyIdMethod::Sha256,
        KeyIdDerivation::Sha384 => KeyIdMethod::Sha384,
        KeyIdDerivation::Sha512 => KeyIdMethod::Sha512,
    })
}

pub(super) fn prepare_self_signed_params(request: SelfSignedRequest) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    params.distinguished_name = prepare_distinguished_name(request.subject.into());

    if let Some(issuer_alternative_name) = &request.issuer_alternative_name {
        params
            .custom_extensions
            .push(prepare_issuer_alternative_name_extension(
                issuer_alternative_name,
            ));
    }

    params
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
fn prepare_issuer_alternative_name_extension(
    data: &IssuerAlternativeNameRequest,
) -> CustomExtension {
    const OID_ISSUER_ALTERNATIVE_NAME: [u64; 4] = [2, 5, 29, 18];

    let names = yasna::construct_der(|writer| {
        writer.write_sequence(|writer| {
            // https://datatracker.ietf.org/doc/html/rfc5280#appendix-A.2
            // GeneralName
            let tag = match &data.r#type {
                IssuerAlternativeNameType::Email => 1, // rfc822Name [1] IA5String
                IssuerAlternativeNameType::Uri => 6,   // uniformResourceIdentifier [6] IA5String
            };

            writer
                .next()
                .write_tagged_implicit(yasna::Tag::context(tag), |writer| {
                    writer.write_ia5_string(&data.name);
                });
        })
    });
    CustomExtension::from_oid_content(&OID_ISSUER_ALTERNATIVE_NAME, names)
}

pub(super) fn parse_csr(csr_pem: &str) -> Result<(CertificateParams, PublicKey), CSRError> {
    let csr = pem::parse(csr_pem)?;
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
            parse_extension(&mut params, extension)?;
        }
    }

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
