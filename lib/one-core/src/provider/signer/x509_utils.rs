use std::sync::Arc;

use rcgen::{
    CertificateParams, CrlDistributionPoint, Issuer as RcgenIssuer, KeyUsagePurpose, SerialNumber,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use shared_types::{CertificateId, KeyId};
use uuid::Uuid;

use crate::error::ContextWithErrorCode;
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::model::key::Key;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::signer::error::SignerError;
use crate::provider::signer::error::SignerError::MissingKeyStorageProvider;
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

pub(super) struct IdentifierInfo<'a> {
    pub identifier: &'a Identifier,
    pub certificate: Option<CertificateId>,
    pub key: Option<KeyId>,
}

pub(super) struct RevocationInfo {
    pub config_name: String,
    pub revocation_method: Option<Arc<dyn RevocationMethod>>,
}

pub(super) struct CaSigningInfo<'a> {
    pub signature_id: Uuid,
    pub cert_issuer: RcgenIssuer<'a, SigningKeyAdapter>,
    pub ca_certificate: &'a Certificate,
}

pub(super) async fn prepare_params_and_ca_issuer<'a>(
    cert_params: &mut CertificateParams,
    identifier_info: IdentifierInfo<'a>,
    revocation_info: RevocationInfo,
    key_provider: Arc<dyn KeyProvider>,
) -> Result<CaSigningInfo<'a>, SignerError> {
    let mut required_ca_cert_key_usages = vec![KeyUsagePurpose::KeyCertSign];

    let revocation_method = revocation_info.revocation_method;
    if revocation_method.is_some() {
        required_ca_cert_key_usages.push(KeyUsagePurpose::CrlSign);
    }

    let SelectedKey::Certificate { certificate, key } = identifier_info
        .identifier
        .select_key(KeySelection {
            key: identifier_info.key,
            certificate: identifier_info.certificate,
            key_filter: Some(KeyFilter::cert_usage_filter(required_ca_cert_key_usages)),
            ..Default::default()
        })
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
                certificate,
                revocation_info.config_name,
                &*revocation_method,
            )
            .await?
        }
    };
    let signing_key = signing_key_adapter(key.clone(), &*key_provider)?;
    let cert_issuer = issuer_from_cert(certificate, signing_key)?;
    Ok(CaSigningInfo {
        signature_id,
        cert_issuer,
        ca_certificate: certificate,
    })
}

pub(super) fn signing_key_adapter(
    key: Key,
    key_provider: &dyn KeyProvider,
) -> Result<SigningKeyAdapter, SignerError> {
    let key_storage = key_provider
        .get_key_storage(&key.storage_type)
        .ok_or(MissingKeyStorageProvider(key.storage_type.to_owned()))?;
    SigningKeyAdapter::new(key, key_storage, tokio::runtime::Handle::current())
        .error_while("creating signing key adapter")
        .map_err(Into::into)
}

pub(super) fn issuer_from_cert(
    certificate: &Certificate,
    signing_key: SigningKeyAdapter,
) -> Result<RcgenIssuer<'_, SigningKeyAdapter>, SignerError> {
    let ca_cert_der = CertificateDer::pem_slice_iter(certificate.chain.as_bytes())
        .next()
        .ok_or(SignerError::MappingError(
            "Empty ca identifier certificate chain".to_string(),
        ))?
        .map_err(SignerError::signing_error)?;
    let issuer = RcgenIssuer::from_ca_cert_der(&ca_cert_der, signing_key)
        .map_err(SignerError::signing_error)?;
    Ok(issuer)
}

pub(super) async fn handle_x509_revocation(
    params: &mut CertificateParams,
    identifier: &Identifier,
    certificate: &Certificate,
    provider_config_name: String,
    revocation_method: &dyn RevocationMethod,
) -> Result<Uuid, SignerError> {
    let (id, revocation_info) = revocation_method
        .add_signature(provider_config_name, identifier, Some(certificate))
        .await
        .error_while("Adding signature to revocation list")?;
    let distribution_point =
        revocation_info
            .credential_status
            .id
            .ok_or(SignerError::MappingError(
                "Missing status id on revocation_info".to_string(),
            ))?;
    params.crl_distribution_points.push(CrlDistributionPoint {
        uris: vec![distribution_point.to_string()],
    });
    params.serial_number = revocation_info
        .serial
        .map(|s| SerialNumber::from_slice(s.as_slice()));
    Ok(id.into())
}
