use std::sync::Arc;

use rcgen::{
    CertificateParams, CrlDistributionPoint, CustomExtension, Issuer as RcgenIssuer,
    KeyUsagePurpose, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use shared_types::{CertificateId, KeyId, SignerId};
use standardized_types::x509::oid;
use uuid::Uuid;
use x509_parser::prelude::{GeneralName, ParsedExtension, X509Certificate};

use super::error::SignerError;
use super::x509_certificate::dto::{IssuerAlternativeNameRequest, IssuerAlternativeNameType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::provider::credential_formatter::model::CredentialStatus;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::util::key_selection::{CertificateFilter, KeyFilter, KeySelection, SelectedKey};

pub(super) struct IdentifierInfo<'a> {
    pub identifier: &'a Identifier,
    pub certificate: Option<CertificateId>,
    pub key: Option<KeyId>,
}

pub(super) struct RevocationInfo {
    pub config_name: SignerId,
    pub revocation_method: Option<Arc<dyn RevocationMethod>>,
}

pub(super) struct CaSigningInfo {
    pub signature_id: Uuid,
    pub ca_certificate: Certificate,
    pub signing_key: SigningKeyAdapter,
}

pub(super) async fn prepare_params_and_ca_issuer(
    cert_params: &mut CertificateParams,
    identifier_info: IdentifierInfo<'_>,
    revocation_info: RevocationInfo,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<CaSigningInfo, SignerError> {
    let mut required_ca_cert_key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let revocation_method = revocation_info.revocation_method;
    if revocation_method.is_some() {
        required_ca_cert_key_usages.push(KeyUsagePurpose::CrlSign);
    }

    let SelectedKey::Certificate { certificate, key } = identifier_info
        .identifier
        .select_key(KeySelection {
            certificate: CertificateFilter::key_usage(required_ca_cert_key_usages)
                .and_id(identifier_info.certificate),
            key: KeyFilter::id(identifier_info.key),
            ..Default::default()
        })
        .await
        .error_while("selecting signing key")?
    else {
        return Err(SignerError::InvalidIssuerIdentifier(
            identifier_info.identifier.id,
        ));
    };

    let signature_id = match revocation_method {
        None => Uuid::new_v4(),
        Some(revocation_method) => {
            handle_x509_revocation(
                cert_params,
                identifier_info.identifier,
                &certificate,
                revocation_info.config_name,
                &*revocation_method,
            )
            .await?
        }
    };
    let signing_key = signing_key_adapter(*key, &*key_provider)?;

    // The CA issuer (and its issuer-alternative-name extension) borrows the certificate's DER, so it
    // is constructed by the caller which owns the returned `ca_certificate`.
    Ok(CaSigningInfo {
        signature_id,
        ca_certificate: *certificate,
        signing_key,
    })
}

pub(super) fn signing_key_adapter(
    key: Key,
    key_provider: &dyn KeyProvider,
) -> Result<SigningKeyAdapter, SignerError> {
    let key_storage = key_provider.get_key_storage(&key.storage_type)?;
    SigningKeyAdapter::new(key, key_storage)
        .error_while("creating signing key adapter")
        .map_err(Into::into)
}

pub(super) fn issuer_from_cert(
    ca_certificate: &Certificate,
    signing_key: SigningKeyAdapter,
) -> Result<
    (
        RcgenIssuer<'_, SigningKeyAdapter>,
        Option<IssuerAlternativeNameRequest>,
    ),
    SignerError,
> {
    let ca_cert_der = CertificateDer::pem_slice_iter(ca_certificate.chain.as_bytes())
        .next()
        .ok_or(SignerError::MappingError(
            "Empty ca identifier certificate chain".to_string(),
        ))?
        .map_err(SignerError::signing_error)?;

    let (_, certificate) =
        x509_parser::parse_x509_certificate(&ca_cert_der).map_err(SignerError::signing_error)?;

    // if parent CA is a self-signed (root) CA - copy over the Issuer Alternative Name (if any)
    let issuer_alternative_name = if certificate.issuer() == certificate.subject() {
        extract_issuer_alternative_name(&certificate)
    } else {
        None
    };

    let issuer = RcgenIssuer::from_ca_cert_der(&ca_cert_der, signing_key)
        .map_err(SignerError::signing_error)?;
    Ok((issuer, issuer_alternative_name))
}

fn extract_issuer_alternative_name(
    certificate: &X509Certificate<'_>,
) -> Option<IssuerAlternativeNameRequest> {
    let issuer_alternative_name =
        certificate
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::IssuerAlternativeName(ian) => Some(ian),
                _ => None,
            })?;

    issuer_alternative_name
        .general_names
        .iter()
        .find_map(|name| match name {
            GeneralName::RFC822Name(name) => Some(IssuerAlternativeNameRequest {
                r#type: IssuerAlternativeNameType::Email,
                name: name.to_string(),
            }),
            GeneralName::URI(name) => Some(IssuerAlternativeNameRequest {
                r#type: IssuerAlternativeNameType::Uri,
                name: name.to_string(),
            }),
            _ => None,
        })
}

async fn handle_x509_revocation(
    params: &mut CertificateParams,
    identifier: &Identifier,
    certificate: &Certificate,
    provider_config_name: SignerId,
    revocation_method: &dyn RevocationMethod,
) -> Result<Uuid, SignerError> {
    let (id, revocation_info) = revocation_method
        .add_signature(provider_config_name, identifier, Some(certificate))
        .await
        .error_while("Adding signature to revocation list")?;
    let CredentialStatus::CRL(distribution_point) = revocation_info.credential_status else {
        return Err(SignerError::MappingError(
            "Missing status id on revocation_info".to_string(),
        ));
    };
    params.crl_distribution_points.push(CrlDistributionPoint {
        uris: vec![distribution_point.to_string()],
    });
    params.serial_number = revocation_info
        .serial
        .map(|s| SerialNumber::from_slice(s.as_slice()));
    Ok(id.into())
}

// https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.7
pub(super) fn prepare_issuer_alternative_name_extension(
    data: &IssuerAlternativeNameRequest,
) -> CustomExtension {
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
    CustomExtension::from_oid_content(oid::extension::ISSUER_ALTERNATIVE_NAME, names)
}
