mod mapper;

use std::sync::Arc;

use rcgen::BasicConstraints::Unconstrained;
use rcgen::{CrlDistributionPoint, IsCa, Issuer as RcgenIssuer, KeyUsagePurpose, SerialNumber};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{Permission, RevocationMethodId};
use time::Duration;
use uuid::Uuid;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::mapper::x509::SigningKeyAdapter;
use crate::model::certificate::Certificate;
use crate::model::key::Key;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::error::SignerError::MissingKeyStorageProvider;
use crate::provider::signer::model::{Feature, SignerCapabilities};
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::provider::signer::x509_certificate::mapper::params_from_request;
use crate::util::key_selection::{KeyFilter, KeySelection, SelectedKey};
use crate::validator::permissions::RequiredPermssions;

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
    config_name: String,
    params: Params,
    key_provider: Arc<dyn KeyProvider>,
    revocation_method_provider: Arc<dyn RevocationMethodProvider>,
    session_provider: Arc<dyn SessionProvider>,
}

impl X509CertificateSigner {
    pub fn new(
        config_name: String,
        params: Params,
        key_provider: Arc<dyn KeyProvider>,
        revocation_method_provider: Arc<dyn RevocationMethodProvider>,
        session_provider: Arc<dyn SessionProvider>,
    ) -> Self {
        Self {
            config_name,
            params,
            key_provider,
            revocation_method_provider,
            session_provider,
        }
    }

    fn signing_key(&self, key: Key) -> Result<SigningKeyAdapter, SignerError> {
        let key_storage = self
            .key_provider
            .get_key_storage(&key.storage_type)
            .ok_or(MissingKeyStorageProvider(key.storage_type.to_owned()))?;

        let signing_key =
            SigningKeyAdapter::new(key, key_storage, tokio::runtime::Handle::current())
                .error_while("creating signing key adapter")?;
        Ok(signing_key)
    }
}

#[async_trait::async_trait]
impl Signer for X509CertificateSigner {
    fn get_capabilities(&self) -> SignerCapabilities {
        let features = if self.params.payload.allow_ca_signing {
            vec![Feature::SupportsSelfSigned]
        } else {
            vec![]
        };
        SignerCapabilities {
            features,
            supported_identifiers: vec![IdentifierType::CertificateAuthority],
            sign_required_permissions: vec![Permission::X509CertificateCreate],
            revoke_required_permissions: vec![Permission::X509CertificateRevoke],
            signing_key_algorithms: vec![KeyAlgorithmType::Ecdsa, KeyAlgorithmType::Eddsa],
            revocation_methods: vec![RevocationType::CRL],
        }
    }

    async fn sign(
        &self,
        issuer: Issuer,
        request: CreateSignatureRequest,
    ) -> Result<CreateSignatureResponseDTO, SignerError> {
        // Check permissions in provider because internal calls for `Issuer::Key` do _not_ go through the service
        RequiredPermssions::at_least_one(self.get_capabilities().sign_required_permissions)
            .check(&*self.session_provider)
            .error_while("validating provider required permissions")?;

        let SignatureValidity { start, end } =
            calculate_signature_validity(self.params.payload.max_validity_duration, &request)?;

        let mut csr_params = params_from_request(request)?;
        let cert_params = &mut csr_params.params;
        // Serial will either be the first 20 bytes of the public key hash (as implemented by rcgen)
        // _or_ provided by the revocation method. Cannot be chosen externally.
        cert_params.serial_number = None;
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

        let (id, chain) = match issuer {
            Issuer::Identifier {
                identifier,
                certificate,
                key,
            } => {
                let mut required_ca_cert_key_usages = vec![KeyUsagePurpose::KeyCertSign];

                let revocation_method = self.revocation_method();
                if revocation_method.is_some() {
                    required_ca_cert_key_usages.push(KeyUsagePurpose::CrlSign);
                }

                let SelectedKey::Certificate { certificate, key } = identifier
                    .select_key(KeySelection {
                        key,
                        certificate,
                        key_filter: Some(KeyFilter::cert_usage_filter(required_ca_cert_key_usages)),
                        ..Default::default()
                    })
                    .error_while("selecting signing key")?
                else {
                    return Err(SignerError::InvalidIssuerIdentifier(identifier.id));
                };

                let signature_id = match revocation_method {
                    None => Uuid::new_v4(),
                    Some(revocation_method) => {
                        let (id, revocation_info) = revocation_method
                            .add_signature(
                                self.config_name.clone(),
                                &identifier,
                                &Some(certificate.clone()),
                            )
                            .await
                            .error_while("Adding signature to revocation list")?;
                        let distribution_point = revocation_info.credential_status.id.ok_or(
                            SignerError::MappingError(
                                "Missing status id on revocation_info".to_string(),
                            ),
                        )?;
                        cert_params
                            .crl_distribution_points
                            .push(CrlDistributionPoint {
                                uris: vec![distribution_point.to_string()],
                            });
                        cert_params.serial_number = revocation_info
                            .serial
                            .map(|s| SerialNumber::from_slice(s.as_slice()));
                        id.into()
                    }
                };

                let content = csr_params
                    .signed_by(&issuer_from_cert(
                        certificate,
                        self.signing_key(key.clone())?,
                    )?)
                    .map_err(SignerError::signing_error)?;
                let chain = format!("{}{}", content.pem(), certificate.chain); // include CA chain
                (signature_id, chain)
            }
            Issuer::Key(key) => {
                let pem = cert_params
                    .self_signed(&self.signing_key(*key)?)
                    .map_err(SignerError::signing_error)?
                    .pem();
                (Uuid::new_v4(), pem)
            }
        };

        Ok(CreateSignatureResponseDTO { id, result: chain })
    }

    fn revocation_method(&self) -> Option<Arc<dyn RevocationMethod>> {
        self.revocation_method_provider
            .get_revocation_method(self.params.revocation_method.as_ref()?)
    }
}

fn issuer_from_cert(
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
