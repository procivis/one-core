mod mapper;

use std::sync::Arc;

use rcgen::BasicConstraints::Unconstrained;
use rcgen::{IsCa, KeyUsagePurpose};
use serde::Deserialize;
use serde_with::{DurationSeconds, serde_as};
use shared_types::{Permission, RevocationMethodId};
use time::Duration;
use uuid::Uuid;

use crate::config::core_config::{IdentifierType, KeyAlgorithmType, RevocationType};
use crate::error::ContextWithErrorCode;
use crate::proto::session_provider::SessionProvider;
use crate::provider::key_storage::provider::KeyProvider;
use crate::provider::revocation::RevocationMethod;
use crate::provider::revocation::provider::RevocationMethodProvider;
use crate::provider::signer::Signer;
use crate::provider::signer::dto::{CreateSignatureRequest, CreateSignatureResponseDTO, Issuer};
use crate::provider::signer::error::SignerError;
use crate::provider::signer::model::{Feature, SignerCapabilities};
use crate::provider::signer::validity::{SignatureValidity, calculate_signature_validity};
use crate::provider::signer::x509_certificate::mapper::params_from_request;
use crate::provider::signer::x509_utils::{
    CaSigningInfo, IdentifierInfo, RevocationInfo, prepare_params_and_ca_issuer,
    signing_key_adapter,
};
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
                let CaSigningInfo {
                    cert_issuer,
                    signature_id,
                    ca_certificate,
                } = prepare_params_and_ca_issuer(
                    cert_params,
                    IdentifierInfo {
                        identifier: &identifier,
                        certificate,
                        key,
                    },
                    RevocationInfo {
                        config_name: self.config_name.clone(),
                        revocation_method: self.revocation_method(),
                    },
                    self.key_provider.clone(),
                )
                .await?;
                let content = csr_params
                    .signed_by(&cert_issuer)
                    .map_err(SignerError::signing_error)?;
                let chain = format!("{}{}", content.pem(), ca_certificate.chain); // include CA chain
                (signature_id, chain)
            }
            Issuer::Key(key) => {
                // Self-signed certificate
                let pem = cert_params
                    .self_signed(&signing_key_adapter(*key, &*self.key_provider)?)
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
