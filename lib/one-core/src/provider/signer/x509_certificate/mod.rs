use std::sync::Arc;

use rcgen::BasicConstraints::Unconstrained;
use rcgen::{
    CertificateSigningRequestParams, CrlDistributionPoint, IsCa, Issuer, KeyUsagePurpose,
    SerialNumber,
};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::RevocationMethodId;
use time::Duration;
use uuid::Uuid;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::certificate::Certificate;
use crate::model::identifier::Identifier;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{
    CreateSignatureRequestDTO, CreateSignatureResponseDTO, RevocationInfo,
};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::error::SignerError::MissingKeyStorageProvider;
use crate::provider::signer::model::SignerCapabilities;
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub payload: PayloadParams,
    pub revocation_method: Option<RevocationMethodId>,
}

#[serde_as]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PayloadParams {
    #[serde_as(as = "DurationSeconds<i64>")]
    pub max_validity_duration: Duration,
    #[serde(default)]
    pub allow_ca_signing: bool,
}
#[derive(Debug, Deserialize)]
struct RequestData {
    csr: String,
}

pub struct X509CertificateSigner {
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
}

impl X509CertificateSigner {
    pub fn new(
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    ) -> Self {
        Self {
            params,
            key_provider,
            revocation_method_provider,
        }
    }
}

#[async_trait::async_trait]
impl Signer for X509CertificateSigner {
    fn get_capabilities(&self) -> SignerCapabilities {
        SignerCapabilities {
            supported_identifiers: vec![IdentifierType::CertificateAuthority],
            sign_required_permissions: vec!["X509_CERTIFICATE_CREATE"],
            revoke_required_permissions: vec!["X509_CERTIFICATE_REVOKE"],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![RevocationType::CRL],
        }
    }

    async fn sign(
        &self,
        issuer: Identifier,
        request: CreateSignatureRequestDTO,
        revocation_info: Option<RevocationInfo>,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        let SignatureValidity { start, end } =
            calculate_signature_validity(self.params.payload.max_validity_duration, &request)?;
        let request_data: RequestData = serde_json::from_value(request.data)?;
        let mut csr_params = CertificateSigningRequestParams::from_pem(&request_data.csr)
            .map_err(|e| SignerError::InvalidPayload(Box::new(e)))?;

        let cert_params = &mut csr_params.params;
        cert_params.use_authority_key_identifier_extension = true;
        if cert_params
            .key_usages
            .contains(&KeyUsagePurpose::KeyCertSign)
        {
            if self.params.payload.allow_ca_signing {
                // This is a CA CSR, add the basic constraints extension
                cert_params.is_ca = IsCa::Ca(Unconstrained);
            } else {
                return Err(SignerError::InvalidPayload(
                    "Key usage `keyCertSign` is not allowed".to_string().into(),
                ));
            }
        }
        cert_params.not_before = start;
        cert_params.not_after = end;

        let mut required_ca_cert_key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let signature_id = match revocation_info {
            None => Uuid::new_v4(),
            Some(RevocationInfo { id, status, serial }) => {
                required_ca_cert_key_usages.push(KeyUsagePurpose::CrlSign);
                let distribution_point = status.id.ok_or(SignerError::MappingError(
                    "Missing status id on revocation_info".to_string(),
                ))?;
                cert_params
                    .crl_distribution_points
                    .push(CrlDistributionPoint {
                        uris: vec![distribution_point.to_string()],
                    });
                cert_params.serial_number = serial.map(|s| SerialNumber::from_slice(s.as_slice()));
                id.into()
            }
        };
        let SelectedKey::Certificate { certificate, key } = issuer
            .select_key(KeySelection {
                key: request.issuer_key,
                certificate: request.issuer_certificate,
                key_filter: Some(KeyFilter::cert_usage_filter(required_ca_cert_key_usages)),
                ..Default::default()
            })
            .error_while("selecting signing key")?
        else {
            return Err(SignerError::InvalidIssuerIdentifier(issuer.id));
        };
        let key_storage = self
            .key_provider
            .get_key_storage(&key.storage_type)
            .ok_or(MissingKeyStorageProvider(key.storage_type.to_owned()))?;

        let signing_key =
            SigningKeyAdapter::new(key.clone(), key_storage, tokio::runtime::Handle::current())
                .error_while("creating signing key adapter")?;

        let content = csr_params
            .signed_by(&issuer_from_cert(certificate, signing_key)?)
            .map_err(SignerError::signing_error)?;

        Ok(CreateSignatureResponseDTO {
            id: signature_id,
            result: format!("{}{}", content.pem(), certificate.chain), // include CA chain
        })
    }

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_method_provider
            .get_revocation_method(self.params.revocation_method.as_ref()?)
    }
}

fn issuer_from_cert(
    certificate: &Certificate,
    signing_key: SigningKeyAdapter,
) -> Result<Issuer<'_, SigningKeyAdapter>, SignerError> {
    let ca_cert_der = CertificateDer::pem_slice_iter(certificate.chain.as_bytes())
        .next()
        .ok_or(SignerError::MappingError(
            "Empty ca identifier certificate chain".to_string(),
        ))?
        .map_err(SignerError::signing_error)?;
    let issuer =
        Issuer::from_ca_cert_der(&ca_cert_der, signing_key).map_err(SignerError::signing_error)?;
    Ok(issuer)
}
